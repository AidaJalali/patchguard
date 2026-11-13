from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from helpers import MockRunner, make_clean, make_crash

import reproducer.bundler as bundler
from models import ReplayReport, ReplayResult, crash_signature
from reproducer.bundler import (
    BundleError,
    FindingContext,
    MinimizationResult,
    build_reproducer,
    create_bundle,
    minimize_input,
    verify_reproducibility,
)


class SeqRunner:
    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def run(self, input_bytes, *, version, build_type, timeout_sec):
        self.calls.append((input_bytes, version, build_type, timeout_sec))
        return self._results.pop(0)


def make_finding(tmp_path: Path, **overrides) -> FindingContext:
    binary = tmp_path / "target"
    binary.write_bytes(b"\x7fELF" + b"x" * 64)
    kwargs = dict(
        finding_id="f1",
        input_bytes=b"AAAA",
        original=make_crash(),
        binary_path=binary,
        input_mode="stdin",
        argv_template=[],
    )
    kwargs.update(overrides)
    return FindingContext(**kwargs)


def make_replay(matched: int, total: int = 3) -> ReplayReport:
    results = [
        ReplayResult(
            attempt=i,
            crashed=True,
            matched=(i <= matched),
            error_type="heap-buffer-overflow",
            signature=crash_signature(make_crash()),
        )
        for i in range(1, total + 1)
    ]
    return ReplayReport(
        finding_id="f1",
        results=results,
        is_deterministic=(matched == total),
        is_flaky=(matched != total),
        test_id="t1",
        version="base",
        build_type="sanitized",
    )


class TestVerifyReproducibility:
    def test_deterministic_crash(self):
        runner = SeqRunner([make_crash(), make_crash(), make_crash()])
        report = verify_reproducibility(runner, b"AAAA", make_crash(), finding_id="f1")
        assert report.is_deterministic is True
        assert report.is_flaky is False
        assert len(report.results) == 3
        assert all(r.matched for r in report.results)

    def test_partial_reproduction_is_flaky(self):
        runner = SeqRunner([make_crash(), make_clean(), make_crash()])
        report = verify_reproducibility(runner, b"AAAA", make_crash(), finding_id="f1")
        assert report.is_flaky is True
        assert report.is_deterministic is False
        assert sum(r.matched for r in report.results) == 2

    def test_changed_signature_is_not_a_match(self):
        runner = SeqRunner([make_crash(), make_crash(line=99), make_crash()])
        report = verify_reproducibility(runner, b"AAAA", make_crash(), finding_id="f1")
        assert report.is_flaky is True
        assert not report.results[1].matched

    def test_timeout_never_matches(self):
        runner = SeqRunner(
            [
                make_crash(),
                make_crash(timed_out=True, crashed=False, exit_code=124),
                make_crash(),
            ]
        )
        report = verify_reproducibility(runner, b"AAAA", make_crash(), finding_id="f1")
        assert report.is_flaky is True
        assert report.results[1].timed_out is True
        assert report.results[1].matched is False

    def test_timeout_even_with_crash_flag_never_matches(self):

        runner = SeqRunner([make_crash(), make_crash(timed_out=True), make_crash()])
        report = verify_reproducibility(runner, b"AAAA", make_crash(), finding_id="f1")
        assert report.is_flaky is True
        assert report.results[1].matched is False

    def test_oom_never_matches(self):
        runner = SeqRunner(
            [make_crash(), make_crash(oom_killed=True, crashed=False), make_crash()]
        )
        report = verify_reproducibility(runner, b"AAAA", make_crash(), finding_id="f1")
        assert report.is_flaky is True
        assert report.results[1].oom_killed is True
        assert report.results[1].matched is False

    def test_replay_count_is_configurable(self):
        runner = SeqRunner([make_crash()] * 5)
        report = verify_reproducibility(
            runner, b"AAAA", make_crash(), finding_id="f1", n=5
        )
        assert len(report.results) == 5
        assert report.is_deterministic is True

    def test_n_must_be_positive(self):
        with pytest.raises(ValueError):
            verify_reproducibility(
                MockRunner(), b"AAAA", make_crash(), finding_id="f1", n=0
            )

    def test_forwards_input_and_settings(self):
        runner = SeqRunner([make_crash(version="patched", build_type="release")] * 3)
        report = verify_reproducibility(
            runner,
            b"AAAA",
            make_crash(version="patched", build_type="release"),
            finding_id="f1",
            n=3,
            timeout_sec=2.5,
        )
        assert all(
            call == (b"AAAA", "patched", "release", 2.5) for call in runner.calls
        )
        assert (report.test_id, report.version, report.build_type) == (
            "t1",
            "patched",
            "release",
        )

    def test_replay_report_carries_execution_provenance(self):
        runner = SeqRunner([make_crash()] * 3)
        report = verify_reproducibility(runner, b"AAAA", make_crash(), finding_id="f1")
        assert (report.test_id, report.version, report.build_type) == (
            "t1",
            "base",
            "sanitized",
        )

    def test_runner_context_mismatch_is_detected(self):

        runner = SeqRunner([make_crash(version="patched"), make_crash(), make_crash()])
        with pytest.raises(ValueError, match="execution context mismatch"):
            verify_reproducibility(runner, b"AAAA", make_crash(), finding_id="f1")

    def test_runner_test_id_mismatch_is_detected(self):
        runner = SeqRunner([make_crash(test_id="other")] * 3)
        with pytest.raises(ValueError, match="execution context mismatch"):
            verify_reproducibility(runner, b"AAAA", make_crash(), finding_id="f1")

    def test_runner_build_type_mismatch_is_detected(self):
        runner = SeqRunner([make_crash(build_type="release")] * 3)
        with pytest.raises(ValueError, match="execution context mismatch"):
            verify_reproducibility(runner, b"AAAA", make_crash(), finding_id="f1")


class TestMinimizeInput:
    def test_minimizes_and_revalidates(self):
        runner = MockRunner(
            default=lambda inp: make_crash() if b"PWN" in inp else make_clean()
        )
        result = minimize_input(runner, b"A" * 200 + b"PWN" + b"B" * 200, make_crash())
        assert result.input_bytes == b"PWN"
        assert result.skipped is False
        assert result.revalidated is True
        assert result.candidate_runs >= 1

    def test_revalidation_failure_keeps_original(self, monkeypatch):

        monkeypatch.setattr(bundler, "ddmin", lambda initial, predicate, **kw: b"PWN")
        runner = MockRunner(
            default=lambda inp: make_crash() if inp != b"PWN" else make_clean()
        )
        result = minimize_input(runner, b"A" * 50 + b"PWN", make_crash())
        assert result.skipped is True
        assert result.skip_reason == "revalidation_failed"
        assert result.revalidated is False
        assert result.input_bytes == b"A" * 50 + b"PWN"

    def test_wrong_context_during_minimization_rejected(self, tmp_path):

        class TwoPhaseRunner:
            def __init__(self):
                self.calls = 0

            def run(self, input_bytes, *, version, build_type, timeout_sec):
                self.calls += 1
                if self.calls <= 3:
                    return make_crash()
                return make_crash(version="patched")

        finding = make_finding(tmp_path, input_bytes=b"AAAPWN")
        with pytest.raises(ValueError, match="execution context mismatch"):
            build_reproducer(finding, TwoPhaseRunner(), output_root=tmp_path / "out")

    def test_wrong_context_on_final_revalidation_rejected(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bundler, "ddmin", lambda initial, predicate, **kw: b"PWN")
        finding = make_finding(tmp_path, input_bytes=b"AAAPWN")
        runner = MockRunner(
            default=lambda inp: make_crash(
                version="patched" if inp == b"PWN" else "base"
            )
        )
        with pytest.raises(ValueError, match="execution context mismatch"):
            minimize_input(runner, finding.input_bytes, finding.original)


class TestCreateBundle:
    def test_happy_path_writes_all_files(self, tmp_path):
        finding = make_finding(tmp_path)
        minimized = MinimizationResult(
            input_bytes=b"PW", candidate_runs=7, revalidated=True
        )
        artifact = create_bundle(
            finding,
            replay=make_replay(3),
            minimized=minimized,
            output_root=tmp_path / "out",
        )
        bundle = tmp_path / "out" / "f1"
        assert (bundle / "crashing_input.bin").read_bytes() == b"AAAA"
        assert (bundle / "minimized_input.bin").read_bytes() == b"PW"
        assert (bundle / "binary").read_bytes() == finding.binary_path.read_bytes()
        assert (bundle / "reproduce.sh").stat().st_mode & 0o111
        assert "eval" not in (bundle / "reproduce.sh").read_text()

        metadata = json.loads((bundle / "metadata.json").read_text())
        assert (
            metadata["binary"]["sha256"]
            == hashlib.sha256((bundle / "binary").read_bytes()).hexdigest()
        )
        assert metadata["replay"]["total"] == 3
        assert metadata["replay"]["matching"] == 3
        assert metadata["replay"]["deterministic"] is True
        assert metadata["minimization"] == {
            "skipped": False,
            "skip_reason": None,
            "algorithm": "ddmin",
            "candidate_runs": 7,
            "revalidated": True,
            "original_size_bytes": 4,
            "minimized_size_bytes": 2,
        }
        assert metadata["crash"]["error_type"] == "heap-buffer-overflow"
        assert metadata["crash"]["top_frame"]["function"] == "copy_data"
        assert metadata["invocation"]["input_mode"] == "stdin"

        assert artifact.deterministic_replays == "3/3"
        assert artifact.is_flaky is False
        assert artifact.original_size_bytes == 4
        assert artifact.minimized_size_bytes == 2
        assert artifact.minimized_input_path == str(bundle / "minimized_input.bin")

    def test_flaky_bundle_preserves_original_and_records_skip(self, tmp_path):
        finding = make_finding(tmp_path)
        minimized = MinimizationResult(
            input_bytes=finding.input_bytes, skipped=True, skip_reason="flaky"
        )
        artifact = create_bundle(
            finding,
            replay=make_replay(1),
            minimized=minimized,
            output_root=tmp_path / "out",
        )
        bundle = tmp_path / "out" / "f1"
        assert (bundle / "minimized_input.bin").read_bytes() == b"AAAA"
        metadata = json.loads((bundle / "metadata.json").read_text())
        assert metadata["minimization"]["skipped"] is True
        assert metadata["minimization"]["skip_reason"] == "flaky"
        assert metadata["minimization"]["algorithm"] is None
        assert metadata["replay"]["matching"] == 1
        assert artifact.is_flaky is True
        assert artifact.deterministic_replays == "1/3"

    def test_output_root_with_spaces_and_special_chars(self, tmp_path):
        finding = make_finding(tmp_path)
        root = tmp_path / "out dir (v1) & co"
        artifact = create_bundle(
            finding,
            replay=make_replay(3),
            minimized=MinimizationResult(input_bytes=b"PW", revalidated=True),
            output_root=root,
        )
        assert (root / "f1" / "crashing_input.bin").is_file()
        assert Path(artifact.bundle_dir).is_dir()

    @pytest.mark.parametrize(
        "bad_id",
        [
            "../evil",
            "a/b",
            "..",
            "",
            ".",
            "x y",
            "x;rm",
            "-flag",
            "a\\b",
        ],
    )
    def test_unsafe_finding_ids_rejected(self, tmp_path, bad_id):
        finding = make_finding(tmp_path, finding_id=bad_id)
        with pytest.raises(BundleError):
            create_bundle(
                finding,
                replay=make_replay(3),
                minimized=MinimizationResult(input_bytes=b"PW"),
                output_root=tmp_path / "out",
            )
        assert not (tmp_path / "evil").exists()

    def test_missing_binary_rejected(self, tmp_path):
        finding = make_finding(tmp_path)
        finding.binary_path = tmp_path / "gone"
        with pytest.raises(BundleError, match="binary not found"):
            create_bundle(
                finding,
                replay=make_replay(3),
                minimized=MinimizationResult(input_bytes=b"PW"),
                output_root=tmp_path / "out",
            )

    def test_argv_template_validation(self, tmp_path):
        bad_findings = [
            make_finding(tmp_path, input_mode="stdin", argv_template=["{input}"]),
            make_finding(tmp_path, input_mode="file", argv_template=[]),
            make_finding(
                tmp_path, input_mode="file", argv_template=["{input}", "{input}"]
            ),
            make_finding(tmp_path, input_mode="socket"),
        ]
        for finding in bad_findings:
            with pytest.raises(BundleError):
                create_bundle(
                    finding,
                    replay=make_replay(3),
                    minimized=MinimizationResult(input_bytes=b"PW"),
                    output_root=tmp_path / "out",
                )

    def test_env_vars_quoted_in_script_and_metadata(self, tmp_path):
        finding = make_finding(tmp_path, env_vars={"FOO": "a b", "X": "1"})
        create_bundle(
            finding,
            replay=make_replay(3),
            minimized=MinimizationResult(input_bytes=b"PW"),
            output_root=tmp_path / "out",
        )
        script = (tmp_path / "out" / "f1" / "reproduce.sh").read_text()

        assert "env 'FOO=a b' X=1 \"$BINARY\"" in script
        assert "export" not in script
        metadata = json.loads((tmp_path / "out" / "f1" / "metadata.json").read_text())
        assert metadata["build"]["env_vars"] == {"FOO": "a b", "X": "1"}

    @pytest.mark.parametrize(
        "bad_env",
        [
            {"BAD NAME": "x"},
            {"X=Y": "z"},
            {"": "x"},
            {"1X": "y"},
        ],
    )
    def test_invalid_env_names_rejected(self, tmp_path, bad_env):
        finding = make_finding(tmp_path, env_vars=bad_env)
        with pytest.raises(BundleError, match="env var"):
            create_bundle(
                finding,
                replay=make_replay(3),
                minimized=MinimizationResult(input_bytes=b"PW"),
                output_root=tmp_path / "out",
            )


class TestBuildReproducer:
    def test_deterministic_pipeline_minimizes(self, tmp_path):
        finding = make_finding(tmp_path, input_bytes=b"A" * 100 + b"PWN")
        runner = MockRunner(
            default=lambda inp: make_crash() if b"PWN" in inp else make_clean()
        )
        artifact = build_reproducer(finding, runner, output_root=tmp_path / "out")
        bundle = Path(artifact.bundle_dir)
        assert artifact.is_flaky is False
        assert (bundle / "minimized_input.bin").read_bytes() == b"PWN"

    def test_flaky_pipeline_skips_minimization(self, tmp_path):
        finding = make_finding(tmp_path, input_bytes=b"AAAA")
        responses = iter([make_crash(), make_clean(), make_crash()])
        runner = MockRunner(default=lambda inp: next(responses))
        artifact = build_reproducer(finding, runner, output_root=tmp_path / "out")
        bundle = Path(artifact.bundle_dir)
        assert artifact.is_flaky is True
        assert (bundle / "minimized_input.bin").read_bytes() == b"AAAA"
        metadata = json.loads((bundle / "metadata.json").read_text())
        assert metadata["minimization"]["skipped"] is True
        assert metadata["minimization"]["skip_reason"] == "flaky"


class TestInsufficientCrashEvidence:
    def test_missing_error_type_and_frames(self, tmp_path):
        finding = make_finding(
            tmp_path, original=make_crash(error_type=None, stack_trace=[])
        )
        runner = MockRunner(
            default=lambda inp: make_crash(error_type=None, stack_trace=[])
        )
        artifact = build_reproducer(finding, runner, output_root=tmp_path / "out")
        assert artifact.is_flaky is True
        bundle = Path(artifact.bundle_dir)
        assert (bundle / "minimized_input.bin").read_bytes() == finding.input_bytes
        metadata = json.loads((bundle / "metadata.json").read_text())
        assert metadata["minimization"]["skipped"] is True
        assert metadata["minimization"]["skip_reason"] == "insufficient_crash_evidence"
        assert metadata["minimization"]["algorithm"] is None

        assert metadata["replay"]["total"] == 3
        assert metadata["replay"]["matching"] == 0

    def test_missing_frames_alone_is_insufficient(self, tmp_path):
        finding = make_finding(tmp_path, original=make_crash(stack_trace=[]))
        runner = MockRunner(default=lambda inp: make_crash(stack_trace=[]))
        artifact = build_reproducer(finding, runner, output_root=tmp_path / "out")
        assert artifact.is_flaky is True
        metadata = json.loads((Path(artifact.bundle_dir) / "metadata.json").read_text())
        assert metadata["minimization"]["skip_reason"] == "insufficient_crash_evidence"

    def test_frames_without_line_info_are_valid_evidence(self, tmp_path):

        finding = make_finding(
            tmp_path,
            input_bytes=b"A" * 100 + b"PWN",
            original=make_crash(line=None),
        )
        runner = MockRunner(
            default=lambda inp: make_crash(line=7) if b"PWN" in inp else make_clean()
        )
        artifact = build_reproducer(finding, runner, output_root=tmp_path / "out")
        assert artifact.is_flaky is False
        assert (
            Path(artifact.bundle_dir) / "minimized_input.bin"
        ).read_bytes() == b"PWN"


class TestNondeterministicAfterReplays:
    def test_precheck_failure_preserves_replay_evidence(self, tmp_path):

        class TwoPhaseRunner:
            def __init__(self):
                self.calls = 0

            def run(self, input_bytes, *, version, build_type, timeout_sec):
                self.calls += 1
                if self.calls <= 3:
                    return make_crash()
                return make_clean()

        finding = make_finding(tmp_path, input_bytes=b"AAAA")
        artifact = build_reproducer(
            finding, TwoPhaseRunner(), output_root=tmp_path / "out"
        )
        assert artifact.is_flaky is True
        assert artifact.deterministic_replays == "3/3"
        bundle = Path(artifact.bundle_dir)
        assert (bundle / "minimized_input.bin").read_bytes() == b"AAAA"
        metadata = json.loads((bundle / "metadata.json").read_text())
        assert metadata["replay"]["matching"] == 3
        assert metadata["minimization"]["skipped"] is True
        assert (
            metadata["minimization"]["skip_reason"]
            == "nondeterministic_precheck_failed"
        )

    def test_failed_revalidation_marks_inconclusive(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bundler, "ddmin", lambda initial, predicate, **kw: b"PWN")
        finding = make_finding(tmp_path, input_bytes=b"AAAPWN")
        runner = MockRunner(
            default=lambda inp: make_crash() if inp != b"PWN" else make_clean()
        )
        artifact = build_reproducer(finding, runner, output_root=tmp_path / "out")
        assert artifact.is_flaky is True
        bundle = Path(artifact.bundle_dir)
        assert (bundle / "minimized_input.bin").read_bytes() == b"AAAPWN"
        metadata = json.loads((bundle / "metadata.json").read_text())
        assert metadata["replay"]["matching"] == 3
        assert metadata["minimization"]["skipped"] is True
        assert metadata["minimization"]["skip_reason"] == "revalidation_failed"


STDIN_CRASH_C = r"""
#include <stdio.h>
#include <string.h>
int main(void) {
    char buf[1024];
    size_t n = fread(buf, 1, sizeof buf, stdin);
    if (n > 0 && memmem(buf, n, "PWN", 3)) { volatile int *p = 0; *p = 0x42; }
    return 0;
}
"""

FILE_CRASH_C = r"""
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    char buf[1024];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (memmem(buf, n, "PWN", 3)) { volatile int *p = 0; *p = 0x42; }
    return 0;
}
"""

ARGS_CRASH_C = r"""
#include <string.h>
int main(int argc, char **argv) {
    if (argc > 1 && strstr(argv[1], "PWN")) { volatile int *p = 0; *p = 0x42; }
    return 0;
}
"""

ENV_ECHO_CRASH_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    printf("INPUT=%s\n", getenv("INPUT") ? getenv("INPUT") : "<unset>");
    printf("BINARY=%s\n", getenv("BINARY") ? getenv("BINARY") : "<unset>");
    printf("SCRIPT_DIR=%s\n", getenv("SCRIPT_DIR") ? getenv("SCRIPT_DIR") : "<unset>");
    printf("NAME=%s\n", getenv("NAME") ? getenv("NAME") : "<unset>");
    fflush(stdout);
    char buf[1024];
    size_t n = fread(buf, 1, sizeof buf, stdin);
    if (n > 0 && memmem(buf, n, "PWN", 3)) { volatile int *p = 0; *p = 0x42; }
    return 0;
}
"""


@pytest.fixture(scope="module")
def crash_fixtures(tmp_path_factory) -> dict[str, Path]:
    build_dir = tmp_path_factory.mktemp("crash_fixtures")
    fixtures = {}
    for name, source in (
        ("stdin", STDIN_CRASH_C),
        ("file", FILE_CRASH_C),
        ("args", ARGS_CRASH_C),
        ("env_echo", ENV_ECHO_CRASH_C),
    ):
        src = build_dir / f"{name}.c"
        src.write_text(source)
        binary = build_dir / name
        proc = subprocess.run(
            ["gcc", str(src), "-o", str(binary)], capture_output=True, text=True
        )
        assert proc.returncode == 0, f"gcc {name} failed: {proc.stderr}"
        fixtures[name] = binary
    return fixtures


class TestReproduceScriptRuns:
    @pytest.mark.parametrize(
        "mode,argv_template",
        [
            ("stdin", []),
            ("file", ["{input}"]),
            ("args", ["{input}", "--flag"]),
        ],
    )
    def test_script_replays_original_and_minimized_from_any_cwd(
        self, tmp_path, crash_fixtures, mode, argv_template
    ):
        input_bytes = b"xxPWNyy" if mode != "args" else b"PWN"
        finding = make_finding(
            tmp_path,
            finding_id="crash1",
            input_bytes=input_bytes,
            binary_path=crash_fixtures[mode],
            input_mode=mode,
            argv_template=argv_template,
        )
        create_bundle(
            finding,
            replay=make_replay(3),
            minimized=MinimizationResult(input_bytes=b"PWN", revalidated=True),
            output_root=tmp_path / "out dir",
        )
        script = tmp_path / "out dir" / "crash1" / "reproduce.sh"

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()

        for arg, expected_status in ([], 139), (["minimized"], 139):
            proc = subprocess.run(
                ["sh", str(script), *arg], cwd=elsewhere, capture_output=True, text=True
            )
            assert proc.returncode == expected_status, (
                f"mode={mode} arg={arg} rc={proc.returncode} stderr={proc.stderr!r}"
            )
            assert f"binary exited with status {expected_status}" in proc.stderr

    def test_script_rejects_unknown_argument(self, tmp_path, crash_fixtures):
        finding = make_finding(
            tmp_path, binary_path=crash_fixtures["stdin"], input_bytes=b"xxPWNyy"
        )
        create_bundle(
            finding,
            replay=make_replay(3),
            minimized=MinimizationResult(input_bytes=b"PWN", revalidated=True),
            output_root=tmp_path / "out",
        )
        proc = subprocess.run(
            ["sh", str(tmp_path / "out" / "f1" / "reproduce.sh"), "bogus"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 2

    def test_script_does_not_crash_on_clean_input(self, tmp_path, crash_fixtures):

        finding = make_finding(
            tmp_path,
            input_bytes=b"harmless",
            binary_path=crash_fixtures["stdin"],
        )
        create_bundle(
            finding,
            replay=make_replay(3),
            minimized=MinimizationResult(input_bytes=b"harmless", revalidated=True),
            output_root=tmp_path / "out",
        )
        proc = subprocess.run(
            ["sh", str(tmp_path / "out" / "f1" / "reproduce.sh")],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0

    def test_env_vars_colliding_with_script_internals(self, tmp_path, crash_fixtures):

        finding = make_finding(
            tmp_path,
            input_bytes=b"xxPWNyy",
            binary_path=crash_fixtures["env_echo"],
            input_mode="stdin",
            env_vars={
                "INPUT": "target-value",
                "BINARY": "target-value",
                "SCRIPT_DIR": "target-value",
                "NAME": "target-value",
            },
        )
        create_bundle(
            finding,
            replay=make_replay(3),
            minimized=MinimizationResult(input_bytes=b"PWN", revalidated=True),
            output_root=tmp_path / "out",
        )
        proc = subprocess.run(
            ["sh", str(tmp_path / "out" / "f1" / "reproduce.sh")],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )

        assert proc.returncode == 139
        for name in ("INPUT", "BINARY", "SCRIPT_DIR", "NAME"):
            assert f"{name}=target-value" in proc.stdout, (
                f"{name} not passed to child: {proc.stdout!r}"
            )
