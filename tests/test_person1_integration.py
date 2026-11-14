import subprocess
from pathlib import Path

import pytest
from conftest import make_config_dict

from builder.builder import DualBuilder
from classifier.verdict import classify_pair
from config.loader import load_target_config
from correlator.correlator import correlate
from diagnostics.parser import DiagnosticsParser
from diff_parser.diff_analyzer import analyze_git
from exceptions import ConfigOrBuildError
from models import BuildArtifact, ExecutionResult, StackFrame, TargetConfig
from oracle.functional_oracle import OracleExpectation, evaluate
from regression_gen.generator import (
    RegressionExpectation,
    VersionExpectation,
    promote_to_regression_suite,
    verify_manifest_entry,
)
from reporter.report_gen import write_reports
from reproducer.bundler import FindingContext, build_reproducer, verify_reproducibility
from runner.adapter import TargetRunnerAdapter
from runner.sandbox import DockerSandboxRunner, input_to_args


def config(tmp_path, mode="stdin"):
    return TargetConfig(
        "fixture", str(tmp_path), "old", "new", "make", "make", "binary", mode
    )


def artifact(tmp_path, version="base", build="sanitized"):
    return BuildArtifact(
        version,
        build,
        "commit",
        str(tmp_path / "binary"),
        "a" * 64,
        "-O1",
        str(tmp_path),
    )


class CapturingSandbox:
    def __init__(self):
        self.calls = []

    def run(self, artifact, config, test_id, input_bytes, args):
        self.calls.append((artifact, config, test_id, input_bytes, args))
        return ExecutionResult(test_id, artifact.version, artifact.build_type, 0)


@pytest.mark.parametrize(
    "mode,payload,template,expected",
    [
        ("stdin", b"PWN\0", ["--flag"], ["--flag"]),
        ("file", b"PWN\0", ["--file", "{input}"], ["--file", "/work/input.bin"]),
        (
            "args",
            b"a\t b\n'c d'",
            ["--flag", "{input}"],
            ["--flag", "a", "b", "'c", "d'"],
        ),
    ],
)
def test_adapter_routes_real_contract_without_mutating_config(
    tmp_path, mode, payload, template, expected
):
    cfg = config(tmp_path, mode)
    transport = CapturingSandbox()
    item = artifact(tmp_path)
    runner = TargetRunnerAdapter(
        {("base", "sanitized"): item},
        cfg,
        test_id="test",
        sandbox=transport,
        argv_template=template,
    )
    result = runner.run(
        payload, version="base", build_type="sanitized", timeout_sec=0.5
    )
    assert type(result) is ExecutionResult
    assert transport.calls[0][1].timeout_sec == 0.5
    assert cfg.timeout_sec == 5
    assert transport.calls[0][2:] == ("test", payload, expected)


def test_adapter_missing_artifact_and_wrong_returned_context(tmp_path):
    runner = TargetRunnerAdapter(
        {}, config(tmp_path), test_id="t", sandbox=CapturingSandbox()
    )
    with pytest.raises(ConfigOrBuildError):
        runner.run(b"", version="base", build_type="sanitized", timeout_sec=1)

    class WrongSandbox:
        def run(self, *args, **kwargs):
            return ExecutionResult("another-test", "base", "sanitized", 0)

    runner = TargetRunnerAdapter(
        {("base", "sanitized"): artifact(tmp_path)},
        config(tmp_path),
        test_id="t",
        sandbox=WrongSandbox(),
    )
    with pytest.raises(ValueError, match="context mismatch"):
        runner.run(b"", version="base", build_type="sanitized", timeout_sec=1)


def test_parser_produces_the_same_models_used_by_other_members(tmp_path):
    parsed = DiagnosticsParser().parse(
        "t",
        artifact(tmp_path),
        134,
        "",
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
        "#0 0x1234 in parse /build/parse.c:12\n",
        False,
        False,
        5,
        "./binary",
    )
    assert type(parsed) is ExecutionResult
    assert type(parsed.stack_trace[0]) is StackFrame
    assert parsed.signal == 6
    assert parsed.stack_trace[0].function == "parse"
    assert parsed.duration_ms == 5


def test_args_delivery_matches_reproducer_whitespace_contract():
    assert input_to_args(b"'a b'\t--flag\n") == ["'a", "b'", "--flag"]
    with pytest.raises(ValueError, match="null"):
        input_to_args(b"a\0b")


def test_all_members_round_trip_with_real_compiler_and_diagnostics(
    tmp_path, vuln_repo, monkeypatch
):
    import yaml

    data = make_config_dict(
        vuln_repo,
        build_cmd_release="gcc -O1 -g -fno-pie -no-pie -o vuln vuln.c",
        build_cmd_sanitized="gcc -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -fno-pie -no-pie -o vuln vuln.c",
    )
    path = tmp_path / "target.yaml"
    path.write_text(yaml.safe_dump(data))
    cfg = load_target_config(str(path))
    builder = DualBuilder()

    def local_fixture_build(directory, command):
        subprocess.run(
            ["bash", "-lc", command],
            cwd=directory,
            check=True,
            capture_output=True,
            timeout=30,
        )

    monkeypatch.setattr(builder, "_docker_build", local_fixture_build)
    monkeypatch.setattr(
        builder,
        "_verify_elf_x86_64",
        lambda p: subprocess.run(
            ["readelf", "-h", str(p)], check=True, capture_output=True
        ),
    )
    artifacts = builder.build_all(cfg, str(tmp_path / "builds"))

    class FixtureTransport(DockerSandboxRunner):
        def run_raw(self, artifact, config, input_bytes=None, args=None):
            result = subprocess.run(
                [artifact.binary_path, *args],
                capture_output=True,
                timeout=config.timeout_sec,
                env={
                    "ASAN_OPTIONS": "detect_leaks=0:symbolize=1",
                    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
                },
            )
            return dict(
                exit_code=result.returncode,
                stdout=result.stdout.decode(),
                stderr=result.stderr.decode(),
                timed_out=False,
                oom_killed=False,
                duration_ms=0,
                cli_command=artifact.binary_path,
            )

    runner = TargetRunnerAdapter(
        artifacts,
        cfg,
        test_id="overflow",
        sandbox=FixtureTransport(enable_gdb_on_release_crash=False),
    )
    payload = b"A" * 12
    base = runner.run(payload, version="base", build_type="sanitized", timeout_sec=5)
    patched = runner.run(
        payload, version="patched", build_type="sanitized", timeout_sec=5
    )
    assert base.crashed and base.error_type == "heap-buffer-overflow"
    assert not patched.crashed and patched.exit_code == 1
    replay = verify_reproducibility(runner, payload, base, finding_id="overflow")
    bundle = build_reproducer(
        FindingContext(
            "overflow",
            payload,
            base,
            Path(artifacts[("base", "sanitized")].binary_path),
            "args",
            ["{input}"],
        ),
        runner,
        output_root=tmp_path / "reproducers",
    )
    assert not bundle.is_flaky
    entry = promote_to_regression_suite(
        bundle,
        RegressionExpectation(
            VersionExpectation(True), VersionExpectation(False, exit_code=1, stdout_kind="exact", stdout_value="", stderr_pattern="input too long")
        ),
        suite_root=tmp_path / "suite",
    )
    assert verify_manifest_entry(
        runner, entry, Path(bundle.minimized_input_path).read_bytes()
    ).ok
    patch = analyze_git(vuln_repo, cfg.base_ref, cfg.patched_ref)
    assert not patch.diagnostics
    oracle = evaluate(
        patched, OracleExpectation("overflow", 1, False, "exact", "", "input too long")
    )
    finding = classify_pair(
        "overflow",
        base,
        patched,
        correlation=correlate("overflow", base, patch),
        base_replay=replay,
        patched_oracle=oracle,
        base_artifact=bundle,
    )
    assert finding.status == "Fixed"
    report = write_reports(
        {
            "target_name": cfg.target_name,
            "findings": [finding.to_dict()],
            "executions": [],
            "base_bug_reproduced": True,
            "patch_fix_verified": True,
            "functional_tests_passed": False,
            "mandatory_checks_complete": False,
        },
        tmp_path / "report.json",
        tmp_path / "SUMMARY.md",
    )
    assert report["exit_code"] == 40
