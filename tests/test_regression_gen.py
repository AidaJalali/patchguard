from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from helpers import make_clean, make_crash

import regression_gen.generator as generator_module
from models import (
    CrashSignature,
    ExecutionResult,
    ReproducerArtifact,
    StackFrame,
)
from regression_gen.generator import (
    ManifestEntry,
    RegressionError,
    RegressionExpectation,
    VerificationReport,
    VersionExpectation,
    load_regression_suite,
    promote_to_regression_suite,
    verify_manifest_entry,
    verify_regression,
)
from reproducer.bundler import FindingContext, MinimizationResult, create_bundle

BUNDLE_SIGNATURE = CrashSignature(
    error_type="heap-buffer-overflow",
    function="copy_data",
    file="src/parse.c",
    line=42,
)
DEFAULT_EXPECTATION = RegressionExpectation(
    base=VersionExpectation(crash=True),
    patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
)


def _default_crash() -> dict:
    return {
        "version": "base",
        "error_type": "heap-buffer-overflow",
        "detection_mechanism": "ASAN",
        "exit_code": 1,
        "signal": 6,
        "top_frame": {"function": "copy_data", "file": "src/parse.c", "line": 42},
        "stack_trace": [
            {"index": 0, "function": "copy_data", "file": "src/parse.c", "line": 42}
        ],
    }


def _record(attempt: int, **overrides) -> dict:
    record = {
        "attempt": attempt,
        "crashed": True,
        "matched": True,
        "timed_out": False,
        "oom_killed": False,
        "error_type": "heap-buffer-overflow",
        "signature": ["heap-buffer-overflow", "copy_data", "src/parse.c", 42],
    }
    record.update(overrides)
    return record


def _replay_results(crash: dict, total: int) -> list:
    top = crash.get("top_frame") or {}
    signature = [
        crash.get("error_type"),
        top.get("function"),
        top.get("file"),
        top.get("line"),
    ]
    return [
        {
            "attempt": i,
            "crashed": True,
            "matched": True,
            "timed_out": False,
            "oom_killed": False,
            "error_type": crash.get("error_type"),
            "signature": signature,
        }
        for i in range(1, total + 1)
    ]


def _vname(finding_id: str, content: bytes) -> str:
    return f"{finding_id}_minimized_{hashlib.sha256(content).hexdigest()[:16]}.bin"


def _with_provenance(
    replay: dict,
    *,
    test_id: str = "t1",
    version: str = "base",
    build_type: str = "sanitized",
) -> dict:
    replay = dict(replay)
    replay.update(test_id=test_id, version=version, build_type=build_type)
    return replay


def write_bundle(
    tmp_path: Path,
    finding_id: str = "f1",
    *,
    input_bytes: bytes = b"PWN",
    minimized: bytes = b"PWN",
    minimization=None,
    replay=None,
    crash=None,
    artifact_flaky: bool = False,
    deterministic_replays: str | None = None,
) -> ReproducerArtifact:

    crash = crash if crash is not None else _default_crash()
    if replay is None:
        replay = {
            "total": 3,
            "matching": 3,
            "deterministic": True,
            "is_flaky": False,
            "test_id": "t1",
            "version": crash.get("version"),
            "build_type": "sanitized",
            "results": _replay_results(crash, 3),
        }
    bundle = tmp_path / "reproducers" / finding_id
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "crashing_input.bin").write_bytes(input_bytes)
    (bundle / "minimized_input.bin").write_bytes(minimized)
    metadata = {
        "finding_id": finding_id,
        "created_at": "2026-11-13T00:00:00+00:00",
        "commit": {"base": "a1b2c3d", "patched": "e4f5a6b"},
        "binary": {
            "source_path": "target",
            "sha256": "x" * 64,
            "dependencies": ["libc.so.6"],
        },
        "build": {"build_type": "sanitized", "compile_flags": "-O1", "env_vars": {}},
        "invocation": {
            "input_mode": "stdin",
            "argv_template": [],
            "cli_command": "./target < in",
        },
        "crash": crash,
        "replay": replay,
        "minimization": minimization
        or {
            "skipped": False,
            "skip_reason": None,
            "algorithm": "ddmin",
            "candidate_runs": 7,
            "revalidated": True,
            "original_size_bytes": len(input_bytes),
            "minimized_size_bytes": len(minimized),
        },
    }
    (bundle / "metadata.json").write_text(json.dumps(metadata))
    matching = replay.get("matching", 3)
    total = replay.get("total", 3)
    return ReproducerArtifact(
        finding_id=finding_id,
        bundle_dir=str(bundle),
        deterministic_replays=deterministic_replays or f"{matching}/{total}",
        is_flaky=artifact_flaky,
        original_size_bytes=len(input_bytes),
        minimized_size_bytes=len(minimized),
        minimized_input_path=str(bundle / "minimized_input.bin"),
    )


def read_manifest(suite_root: Path) -> dict:
    return json.loads((suite_root / "auto_generated" / "manifest.json").read_text())


class TestPromotionEligibility:
    def test_promotes_byte_exact_input_and_manifest(self, tmp_path):
        artifact = write_bundle(tmp_path, input_bytes=b"AAA", minimized=b"PWN")
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        versioned_name = _vname("f1", b"PWN")
        input_file = tmp_path / "suite" / "auto_generated" / versioned_name
        assert input_file.read_bytes() == b"PWN"
        assert entry.input_sha256 == hashlib.sha256(b"PWN").hexdigest()

        manifest = read_manifest(tmp_path / "suite")
        assert manifest["format"] == 2
        stored = manifest["entries"]["f1"]
        assert stored["input_path"] == versioned_name
        assert stored["source_bundle"] == str(tmp_path / "reproducers" / "f1")
        assert stored["build_type"] == "sanitized"
        assert stored["compile_flags"] == "-O1"
        assert stored["commit"] == {"base": "a1b2c3d", "patched": "e4f5a6b"}
        assert stored["input_mode"] == "stdin"
        assert stored["argv_template"] == []
        assert stored["expected"]["base"] == {
            "crash": True,
            "signature": {
                "error_type": "heap-buffer-overflow",
                "function": "copy_data",
                "file": "src/parse.c",
                "line": 42,
            },
            "test_id": "t1",
        }
        assert stored["expected"]["patched"] == {
            "crash": False,
            "exit_code": 0,
            "test_id": "t1",
            "oracle": {"stdout_kind": "exact", "stdout_value": "ok", "stderr_pattern": None},
        }

    def test_rejects_flaky_artifact_even_with_three_of_three(self, tmp_path):
        artifact = write_bundle(
            tmp_path, artifact_flaky=True, deterministic_replays="3/3"
        )
        with pytest.raises(RegressionError, match="inconclusive"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()

    def test_rejects_skipped_minimization(self, tmp_path):
        artifact = write_bundle(
            tmp_path,
            minimization={
                "skipped": True,
                "skip_reason": "flaky",
                "revalidated": False,
                "candidate_runs": 0,
                "original_size_bytes": 3,
                "minimized_size_bytes": 3,
            },
            replay={
                "total": 3,
                "matching": 3,
                "deterministic": True,
                "is_flaky": True,
                "results": [],
            },
        )
        with pytest.raises(RegressionError, match="minimization was skipped"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    @pytest.mark.parametrize("revalidated", [False, None])
    def test_rejects_unrevalidated_minimization(self, tmp_path, revalidated):
        artifact = write_bundle(
            tmp_path,
            minimization={
                "skipped": False,
                "skip_reason": None,
                "algorithm": "ddmin",
                "candidate_runs": 7,
                "revalidated": revalidated,
                "original_size_bytes": 3,
                "minimized_size_bytes": 3,
            },
        )
        with pytest.raises(RegressionError, match="not revalidated|not .*revalidated"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_rejects_missing_bundle_metadata(self, tmp_path):
        artifact = write_bundle(tmp_path)
        (tmp_path / "reproducers" / "f1" / "metadata.json").unlink()
        with pytest.raises(RegressionError, match="metadata not found"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_rejects_corrupted_bundle_metadata(self, tmp_path):
        artifact = write_bundle(tmp_path)
        (tmp_path / "reproducers" / "f1" / "metadata.json").write_text("{not json")
        with pytest.raises(RegressionError, match="corrupted"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_rejects_replay_inconsistency(self, tmp_path):
        artifact = write_bundle(
            tmp_path,
            replay=_with_provenance(
                {
                    "total": 3,
                    "matching": 2,
                    "deterministic": False,
                    "is_flaky": True,
                    "results": [],
                },
            ),
        )
        with pytest.raises(RegressionError, match="replay evidence inconsistent"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_rejects_artifact_bundle_replay_mismatch(self, tmp_path):
        artifact = write_bundle(tmp_path, deterministic_replays="2/3")
        with pytest.raises(RegressionError, match="artifact reports"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_rejects_flaky_bundle_metadata(self, tmp_path):
        artifact = write_bundle(
            tmp_path,
            replay=_with_provenance(
                {
                    "total": 3,
                    "matching": 3,
                    "deterministic": True,
                    "is_flaky": True,
                    "results": [],
                },
            ),
        )
        with pytest.raises(RegressionError, match="flaky"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_rejects_missing_minimized_input_file(self, tmp_path):
        artifact = write_bundle(tmp_path)
        (tmp_path / "reproducers" / "f1" / "minimized_input.bin").unlink()
        with pytest.raises(RegressionError, match="minimized input not found"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_rejects_insufficient_bundle_crash_evidence(self, tmp_path):
        artifact = write_bundle(
            tmp_path,
            crash={
                "version": "base",
                "error_type": None,
                "top_frame": None,
                "stack_trace": [],
            },
        )
        with pytest.raises(RegressionError, match="insufficient"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_insufficient_bundle_evidence_rejected_even_with_override(self, tmp_path):

        artifact = write_bundle(
            tmp_path,
            crash={
                "version": "base",
                "error_type": None,
                "top_frame": None,
                "stack_trace": [],
            },
        )
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=True, signature=BUNDLE_SIGNATURE),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
        )
        with pytest.raises(RegressionError, match="insufficient"):
            promote_to_regression_suite(
                artifact, expectation, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()

    def test_new_issue_in_patched_with_signature_override(self, tmp_path):

        artifact = write_bundle(tmp_path)
        new_issue = CrashSignature(
            error_type="null-dereference",
            function="other_fn",
            file="src/new.c",
            line=7,
        )
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
            patched=VersionExpectation(crash=True, signature=new_issue),
        )
        entry = promote_to_regression_suite(
            artifact, expectation, suite_root=tmp_path / "suite"
        )
        assert entry.expected["base"] == {
            "crash": False,
            "exit_code": 0,
            "test_id": "t1",
            "oracle": {"stdout_kind": "exact", "stdout_value": "ok", "stderr_pattern": None},
        }
        assert entry.expected["patched"]["crash"] is True
        assert entry.expected["patched"]["signature"]["function"] == "other_fn"
        assert entry.expected["patched"]["test_id"] == "t1"

    def test_rejects_all_clean_expectations(self, tmp_path):
        artifact = write_bundle(tmp_path)
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
        )
        with pytest.raises(RegressionError, match="at least one version"):
            promote_to_regression_suite(
                artifact, expectation, suite_root=tmp_path / "suite"
            )

    def test_rejects_clean_expectation_without_exit_code(self, tmp_path):
        artifact = write_bundle(tmp_path)
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=True),
            patched=VersionExpectation(crash=False),
        )
        with pytest.raises(RegressionError, match="requires an explicit exit_code"):
            promote_to_regression_suite(
                artifact, expectation, suite_root=tmp_path / "suite"
            )


class TestManifestWriting:
    def test_idempotent_promotion(self, tmp_path):
        artifact = write_bundle(tmp_path)
        first = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        second = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        assert second.to_dict() == first.to_dict()
        manifest = read_manifest(tmp_path / "suite")
        assert list(manifest["entries"]) == ["f1"]
        assert (
            tmp_path / "suite" / "auto_generated" / first.input_path
        ).read_bytes() == b"PWN"

    def test_conflicting_entry_requires_replace(self, tmp_path):
        artifact = write_bundle(tmp_path, minimized=b"PWN")
        promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        auto = tmp_path / "suite" / "auto_generated"
        old_name = _vname("f1", b"PWN")

        changed = write_bundle(tmp_path, minimized=b"DIFF")
        with pytest.raises(RegressionError, match="conflicting"):
            promote_to_regression_suite(
                changed, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

        assert (auto / old_name).read_bytes() == b"PWN"

        entry = promote_to_regression_suite(
            changed,
            DEFAULT_EXPECTATION,
            suite_root=tmp_path / "suite",
            replace=True,
        )
        new_name = _vname("f1", b"DIFF")
        assert entry.input_path == new_name
        assert (auto / new_name).read_bytes() == b"DIFF"
        assert entry.input_sha256 == hashlib.sha256(b"DIFF").hexdigest()

        assert (auto / old_name).read_bytes() == b"PWN"

    def test_conflict_when_same_entry_but_input_file_modified(self, tmp_path):
        artifact = write_bundle(tmp_path)
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        input_file = tmp_path / "suite" / "auto_generated" / entry.input_path
        input_file.write_bytes(b"tampered")
        with pytest.raises(RegressionError, match="conflicting"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_multiple_entries_preserved(self, tmp_path):
        first = write_bundle(tmp_path, finding_id="f1", minimized=b"AAA")
        promote_to_regression_suite(
            first, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        second = write_bundle(tmp_path, finding_id="f2", minimized=b"BBB")
        promote_to_regression_suite(
            second, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        manifest = read_manifest(tmp_path / "suite")
        assert set(manifest["entries"]) == {"f1", "f2"}
        auto = tmp_path / "suite" / "auto_generated"
        for finding_id, content in (("f1", b"AAA"), ("f2", b"BBB")):
            entry = manifest["entries"][finding_id]
            assert (auto / entry["input_path"]).read_bytes() == content
            assert entry["input_sha256"] == hashlib.sha256(content).hexdigest()

    @pytest.mark.parametrize("bad_id", ["../evil", "a/b", "x y", "..", ""])
    def test_invalid_ids_and_traversal_rejected(self, tmp_path, bad_id):
        artifact = write_bundle(tmp_path, finding_id="f1")
        artifact.finding_id = bad_id
        with pytest.raises(RegressionError, match="invalid finding_id"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()
        assert not (tmp_path / "evil").exists()

    def test_corrupted_existing_manifest_not_overwritten(self, tmp_path):
        auto = tmp_path / "suite" / "auto_generated"
        auto.mkdir(parents=True)
        manifest_path = auto / "manifest.json"
        garbage = "{corrupted json!!"
        manifest_path.write_text(garbage)
        artifact = write_bundle(tmp_path)
        with pytest.raises(RegressionError, match="corrupted"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert manifest_path.read_text() == garbage

    def test_unexpected_manifest_structure_rejected(self, tmp_path):
        auto = tmp_path / "suite" / "auto_generated"
        auto.mkdir(parents=True)
        (auto / "manifest.json").write_text(json.dumps(["not", "a", "dict"]))
        artifact = write_bundle(tmp_path)
        with pytest.raises(RegressionError, match="unexpected structure"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )


class VersionedRunner:
    def __init__(self, base: ExecutionResult, patched: ExecutionResult):
        if base.version != "base" or patched.version != "patched":
            raise AssertionError(
                "scripted results must carry version 'base'/'patched' "
                f"respectively, got {base.version!r}/{patched.version!r}"
            )
        self._base, self._patched = base, patched
        self.calls = []

    def run(self, input_bytes, *, version, build_type, timeout_sec):
        self.calls.append((input_bytes, version, build_type, timeout_sec))
        return self._base if version == "base" else self._patched


EXPECTATION = RegressionExpectation(
    base=VersionExpectation(crash=True, signature=BUNDLE_SIGNATURE, test_id="t1"),
    patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0, test_id="t1"),
)


class TestVerificationHelper:
    def test_matching_signatures_pass(self):
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        report = verify_regression(runner, b"PWN", EXPECTATION, build_type="sanitized")
        assert isinstance(report, VerificationReport)
        assert report.ok is True
        assert report.base.ok and "matched" in report.base.reason
        assert report.patched.ok and "as expected" in report.patched.reason

    def test_mismatching_crash_signature_fails(self):
        runner = VersionedRunner(
            base=make_crash(line=99), patched=make_clean(version="patched")
        )
        report = verify_regression(runner, b"PWN", EXPECTATION, build_type="sanitized")
        assert report.ok is False
        assert report.base.ok is False
        assert "mismatch" in report.base.reason
        assert report.patched.ok is True

    def test_patched_crash_where_clean_expected_fails(self):
        runner = VersionedRunner(
            base=make_crash(), patched=make_crash(version="patched")
        )
        report = verify_regression(runner, b"PWN", EXPECTATION, build_type="sanitized")
        assert report.ok is False
        assert "clean exit was expected" in report.patched.reason

    def test_timeout_does_not_satisfy_crash_expectation(self):
        runner = VersionedRunner(
            base=make_crash(timed_out=True), patched=make_clean(version="patched")
        )
        report = verify_regression(runner, b"PWN", EXPECTATION, build_type="sanitized")
        assert report.base.ok is False
        assert "timed out" in report.base.reason

    def test_oom_does_not_satisfy_clean_expectation(self):
        runner = VersionedRunner(
            base=make_crash(),
            patched=make_clean(version="patched", oom_killed=True, crashed=False),
        )
        report = verify_regression(runner, b"PWN", EXPECTATION, build_type="sanitized")
        assert report.patched.ok is False
        assert "OOM-killed" in report.patched.reason

    def test_explicit_nonzero_exit_code(self):
        expectation = RegressionExpectation(
            base=VersionExpectation(
                crash=True, signature=BUNDLE_SIGNATURE, test_id="t1"
            ),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=3, test_id="t1"),
        )
        ok_runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched", exit_code=3)
        )
        assert (
            verify_regression(ok_runner, b"PWN", expectation, build_type="sanitized").ok
            is True
        )

        wrong_runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched", exit_code=0)
        )
        report = verify_regression(
            wrong_runner, b"PWN", expectation, build_type="sanitized"
        )
        assert report.patched.ok is False
        assert "exit_code 0 != expected 3" in report.patched.reason

    def test_exit_code_checked_on_crash_when_provided(self):
        expectation = RegressionExpectation(
            base=VersionExpectation(
                crash=True, signature=BUNDLE_SIGNATURE, exit_code=1, test_id="t1"
            ),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0, test_id="t1"),
        )
        runner = VersionedRunner(
            base=make_crash(exit_code=134), patched=make_clean(version="patched")
        )
        report = verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert report.base.ok is False
        assert "exit_code 134 != expected 1" in report.base.reason

    def test_infrastructure_failure_propagates(self):
        class FailingRunner:
            def run(self, input_bytes, *, version, build_type, timeout_sec):
                raise RuntimeError("docker daemon down")

        with pytest.raises(RuntimeError, match="docker"):
            verify_regression(
                FailingRunner(), b"PWN", EXPECTATION, build_type="sanitized"
            )

    def test_forwards_version_build_and_timeout(self):
        runner = VersionedRunner(
            base=make_crash(build_type="release"),
            patched=make_clean(version="patched", build_type="release"),
        )
        verify_regression(
            runner, b"PWN", EXPECTATION, build_type="release", timeout_sec=2.5
        )
        assert runner.calls == [
            (b"PWN", "base", "release", 2.5),
            (b"PWN", "patched", "release", 2.5),
        ]

    def test_insufficient_expected_signature_rejected(self):
        expectation = RegressionExpectation(
            base=VersionExpectation(
                crash=True,
                signature=CrashSignature(
                    error_type=None, function=None, file=None, line=None
                ),
            ),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
        )
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        with pytest.raises(RegressionError, match="insufficient evidence"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")

    def test_unresolved_signature_rejected(self):
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=True, signature=None),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
        )
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        with pytest.raises(RegressionError, match="resolved signature"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")


class TestVerifyRegressionValidation:
    def _runner(self) -> VersionedRunner:
        return VersionedRunner(base=make_crash(), patched=make_clean(version="patched"))

    def _expectation(self, **overrides) -> RegressionExpectation:
        kwargs = dict(
            base=VersionExpectation(
                crash=True, signature=BUNDLE_SIGNATURE, test_id="t1"
            ),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0, test_id="t1"),
        )
        kwargs.update(overrides)
        return RegressionExpectation(**kwargs)

    @pytest.mark.parametrize("bad_crash", ["false", "true", 0, 1])
    def test_non_bool_crash_rejected_with_zero_calls(self, bad_crash):
        expectation = self._expectation(
            base=VersionExpectation(crash=bad_crash, signature=BUNDLE_SIGNATURE),
        )
        runner = self._runner()
        with pytest.raises(RegressionError, match="actual boolean"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert runner.calls == []

    @pytest.mark.parametrize("bad_exit", [True, False, "3", 3.5])
    def test_invalid_exit_code_types_rejected_with_zero_calls(self, bad_exit):
        expectation = self._expectation(
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=bad_exit),
        )
        runner = self._runner()
        with pytest.raises(RegressionError, match="integer"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert runner.calls == []

    def test_clean_expectation_without_exit_code_rejected(self):
        expectation = self._expectation(
            patched=VersionExpectation(crash=False),
        )
        runner = self._runner()
        with pytest.raises(RegressionError, match="requires an explicit exit_code"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert runner.calls == []

    def test_crash_expectation_without_signature_rejected(self):
        expectation = self._expectation(
            base=VersionExpectation(crash=True),
        )
        runner = self._runner()
        with pytest.raises(RegressionError, match="requires a resolved signature"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert runner.calls == []

    def test_crash_expectation_with_insufficient_signature_rejected(self):
        expectation = self._expectation(
            base=VersionExpectation(
                crash=True,
                signature=CrashSignature(None, None, None, None),
            ),
        )
        runner = self._runner()
        with pytest.raises(RegressionError, match="insufficient evidence"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert runner.calls == []

    def test_invalid_patched_zero_calls_even_with_valid_base(self):

        expectation = self._expectation(
            patched=VersionExpectation(crash="false", signature=BUNDLE_SIGNATURE),
        )
        runner = self._runner()
        with pytest.raises(RegressionError, match="actual boolean"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert runner.calls == []

    def test_invalid_base_zero_calls(self):
        expectation = self._expectation(
            base=VersionExpectation(crash=False),
        )
        runner = self._runner()
        with pytest.raises(RegressionError, match="requires an explicit exit_code"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert runner.calls == []

    def test_malformed_expectation_objects_fail_cleanly(self):
        runner = self._runner()
        with pytest.raises(RegressionError, match="RegressionExpectation"):
            verify_regression(
                runner, b"PWN", {"base": {}, "patched": {}}, build_type="sanitized"
            )
        malformed = self._expectation(base="not-a-VersionExpectation")
        with pytest.raises(RegressionError, match="must be a VersionExpectation"):
            verify_regression(runner, b"PWN", malformed, build_type="sanitized")
        assert runner.calls == []

    def test_valid_expectations_still_verify(self):
        runner = self._runner()
        report = verify_regression(
            runner, b"PWN", self._expectation(), build_type="sanitized"
        )
        assert report.ok is True
        assert [call[1] for call in runner.calls] == ["base", "patched"]

    def test_valid_nonzero_exit_code_still_works(self):
        expectation = self._expectation(
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=3, test_id="t1"),
        )
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched", exit_code=3)
        )
        assert (
            verify_regression(runner, b"PWN", expectation, build_type="sanitized").ok
            is True
        )

    def test_infrastructure_exceptions_still_propagate(self):
        class FailingRunner:
            def run(self, input_bytes, *, version, build_type, timeout_sec):
                raise RuntimeError("sandbox unavailable")

        with pytest.raises(RuntimeError, match="sandbox"):
            verify_regression(
                FailingRunner(), b"PWN", self._expectation(), build_type="sanitized"
            )


class TestMalformedSignatureValidation:
    def _runner(self) -> VersionedRunner:
        return VersionedRunner(base=make_crash(), patched=make_clean(version="patched"))

    @pytest.mark.parametrize(
        "bad_signature",
        [
            {"error_type": "heap-buffer-overflow", "function": "copy_data"},
            "copy_data",
            42,
            ["heap-buffer-overflow", "copy_data", "src/parse.c", 42],
            True,
        ],
    )
    def test_malformed_signature_types_rejected_with_zero_calls(self, bad_signature):
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=True, signature=bad_signature),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
        )
        runner = self._runner()
        with pytest.raises(RegressionError, match="must be a CrashSignature"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert runner.calls == []

    def test_malformed_patched_signature_zero_calls(self):
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=True, signature=BUNDLE_SIGNATURE),
            patched=VersionExpectation(crash=True, signature="bad"),
        )
        runner = self._runner()
        with pytest.raises(RegressionError, match="must be a CrashSignature"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert runner.calls == []

    def test_python_api_does_not_convert_dict_signatures(self, tmp_path):

        artifact = write_bundle(tmp_path)
        expectation = RegressionExpectation(
            base=VersionExpectation(
                crash=True,
                signature={
                    "error_type": "heap-buffer-overflow",
                    "function": "copy_data",
                    "file": "src/parse.c",
                    "line": 42,
                },
            ),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
        )
        with pytest.raises(RegressionError, match="must be a CrashSignature"):
            promote_to_regression_suite(
                artifact, expectation, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()

    def test_valid_crash_signature_still_works(self):
        expectation = RegressionExpectation(
            base=VersionExpectation(
                crash=True, signature=BUNDLE_SIGNATURE, test_id="t1"
            ),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0, test_id="t1"),
        )
        runner = self._runner()
        assert (
            verify_regression(runner, b"PWN", expectation, build_type="sanitized").ok
            is True
        )

    def test_manifest_deserialization_still_converts(self, tmp_path):
        artifact = write_bundle(tmp_path)
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        assert verify_manifest_entry(runner, entry, b"PWN").ok is True


class TestVerifyRegressionContextEnforcement:
    def test_swapped_base_patched_results_cannot_pass(self):
        class SwappedRunner:
            def run(self, input_bytes, *, version, build_type, timeout_sec):
                if version == "base":
                    return make_crash(version="patched")
                return make_clean(version="base")

        expectation = RegressionExpectation(
            base=VersionExpectation(
                crash=True, signature=BUNDLE_SIGNATURE, test_id="t1"
            ),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0, test_id="t1"),
        )
        with pytest.raises(ValueError, match="execution context mismatch"):
            verify_regression(
                SwappedRunner(), b"PWN", expectation, build_type="sanitized"
            )

    def test_wrong_build_type_rejected(self):
        class WrongBuildRunner:
            def run(self, input_bytes, *, version, build_type, timeout_sec):
                return make_crash(version=version, build_type="release")

        expectation = RegressionExpectation(
            base=VersionExpectation(
                crash=True, signature=BUNDLE_SIGNATURE, test_id="t1"
            ),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0, test_id="t1"),
        )
        with pytest.raises(ValueError, match="build_type"):
            verify_regression(
                WrongBuildRunner(), b"PWN", expectation, build_type="sanitized"
            )

    def test_expected_test_id_mismatch_rejected(self):
        expectation = RegressionExpectation(
            base=VersionExpectation(
                crash=True, signature=BUNDLE_SIGNATURE, test_id="t1"
            ),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0, test_id="t1"),
        )
        runner = VersionedRunner(
            base=make_crash(test_id="other"),
            patched=make_clean(version="patched", test_id="other"),
        )
        with pytest.raises(ValueError, match="test_id"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")

    def test_matching_test_id_works(self):
        expectation = RegressionExpectation(
            base=VersionExpectation(
                crash=True, signature=BUNDLE_SIGNATURE, test_id="t1"
            ),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0, test_id="t1"),
        )
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        assert (
            verify_regression(runner, b"PWN", expectation, build_type="sanitized").ok
            is True
        )

    def test_legacy_entries_without_test_id_rejected(self):

        entry = make_entry(
            {
                "base": {"crash": True, "signature": GOOD_BASE["signature"]},
                "patched": {"crash": False, "exit_code": 0, "oracle": {"stdout_kind": "exact", "stdout_value": "ok"}},
            }
        )
        runner = VersionedRunner(
            base=make_crash(test_id="other"),
            patched=make_clean(version="patched", test_id="other"),
        )
        with pytest.raises(RegressionError, match="missing expected test provenance"):
            verify_manifest_entry(runner, entry, b"PWN")
        assert runner.calls == []

    def test_direct_api_requires_test_provenance_with_zero_calls(self):
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=True, signature=BUNDLE_SIGNATURE),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
        )
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        with pytest.raises(RegressionError, match="missing expected test provenance"):
            verify_regression(runner, b"PWN", expectation, build_type="sanitized")
        assert runner.calls == []


class TestLoadRegressionSuite:
    def test_loads_saved_entries_with_content(self, tmp_path):
        artifact = write_bundle(tmp_path)
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        loaded = load_regression_suite(tmp_path / "suite")
        assert len(loaded) == 1
        loaded_entry, content = loaded[0]
        assert loaded_entry.finding_id == entry.finding_id
        assert content == b"PWN"
        assert loaded_entry.input_sha256 == hashlib.sha256(content).hexdigest()

    def test_empty_suite_loads_cleanly(self, tmp_path):
        assert load_regression_suite(tmp_path / "suite") == []

    def test_tampered_saved_input_rejected(self, tmp_path):
        artifact = write_bundle(tmp_path)
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        input_path = tmp_path / "suite" / "auto_generated" / entry.input_path
        input_path.write_bytes(b"tampered")
        with pytest.raises(RegressionError, match="integrity check failed"):
            load_regression_suite(tmp_path / "suite")

    def test_symlinked_saved_input_rejected(self, tmp_path):
        artifact = write_bundle(tmp_path)
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        input_path = tmp_path / "suite" / "auto_generated" / entry.input_path
        decoy = tmp_path / "decoy.bin"
        decoy.write_bytes(b"PWN")
        input_path.unlink()
        os.symlink(decoy, input_path)
        with pytest.raises(RegressionError, match="non-symlink"):
            load_regression_suite(tmp_path / "suite")

    def test_key_id_mismatch_rejected(self, tmp_path):
        artifact = write_bundle(tmp_path)
        promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        manifest_path = tmp_path / "suite" / "auto_generated" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        row = manifest["entries"].pop("f1")
        manifest["entries"]["other"] = row
        manifest_path.write_text(json.dumps(manifest))
        with pytest.raises(RegressionError, match="does not match finding ID"):
            load_regression_suite(tmp_path / "suite")


class TestManifestEntryRoundTrip:
    def test_promote_then_verify_via_manifest_entry(self, tmp_path):
        artifact = write_bundle(tmp_path)
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        report = verify_manifest_entry(runner, entry, b"PWN")
        assert report.ok is True
        assert runner.calls[0][2] == "sanitized"


CRASH_C = r"""
#include <stdio.h>
#include <string.h>
int main(void) {
    char buf[1024];
    size_t n = fread(buf, 1, sizeof buf, stdin);
    if (n > 0 && memmem(buf, n, "PWN", 3)) { volatile int *p = 0; *p = 0x42; }
    return 0;
}
"""

SAFE_C = r"""
#include <stdio.h>
int main(void) {
    char buf[1024];
    while (fread(buf, 1, sizeof buf, stdin) > 0) {}
    return 0;
}
"""


class TwoBinaryRunner:
    def __init__(self, base_binary: Path, patched_binary: Path):
        self._binaries = {"base": base_binary, "patched": patched_binary}

    def run(self, input_bytes, *, version, build_type, timeout_sec):
        proc = subprocess.run(
            [str(self._binaries[version])],
            input=input_bytes,
            capture_output=True,
            timeout=30,
        )
        crashed = proc.returncode != 0
        return ExecutionResult(
            test_id="t1",
            version=version,
            build_type=build_type,
            exit_code=proc.returncode,
            signal=11 if crashed else None,
            crashed=crashed,
            error_type="unclassified-crash" if crashed else None,
            detection_mechanism="OS_SIGNAL" if crashed else None,
            stack_trace=[StackFrame(index=0, function="main", file="crash.c", line=9)]
            if crashed
            else [],
            stderr=proc.stderr.decode(errors="replace"),
        )


@pytest.fixture(scope="module")
def real_bundle_and_runner(tmp_path_factory):
    build_dir = tmp_path_factory.mktemp("regression_integration")
    binaries = {}
    for name, source in (("crash", CRASH_C), ("safe", SAFE_C)):
        src = build_dir / f"{name}.c"
        src.write_text(source)
        binary = build_dir / name
        proc = subprocess.run(
            ["gcc", str(src), "-o", str(binary)], capture_output=True, text=True
        )
        assert proc.returncode == 0, f"gcc {name} failed: {proc.stderr}"
        binaries[name] = binary

    original = ExecutionResult(
        test_id="t1",
        version="base",
        build_type="release",
        exit_code=139,
        signal=11,
        crashed=True,
        error_type="unclassified-crash",
        detection_mechanism="OS_SIGNAL",
        stack_trace=[StackFrame(index=0, function="main", file="crash.c", line=9)],
        stderr="Segmentation fault",
    )
    finding = FindingContext(
        finding_id="int1",
        input_bytes=b"xxPWNyy",
        original=original,
        binary_path=binaries["crash"],
        input_mode="stdin",
        cli_command="./crash < crashing_input.bin",
        base_commit_hash="abc",
        patched_commit_hash="def",
        compile_flags="-O2",
    )
    from models import ReplayReport, ReplayResult, crash_signature

    results = [
        ReplayResult(
            attempt=i,
            crashed=True,
            matched=True,
            error_type="unclassified-crash",
            signature=crash_signature(original),
        )
        for i in (1, 2, 3)
    ]
    replay = ReplayReport(
        finding_id="int1",
        results=results,
        is_deterministic=True,
        is_flaky=False,
        test_id=original.test_id,
        version=original.version,
        build_type=original.build_type,
    )
    artifact = create_bundle(
        finding,
        replay=replay,
        minimized=MinimizationResult(
            input_bytes=b"PWN", candidate_runs=5, revalidated=True
        ),
        output_root=build_dir / "reproducers",
    )
    runner = TwoBinaryRunner(binaries["crash"], binaries["safe"])
    return build_dir, artifact, runner


class TestIntegrationWithRealFixtures:
    def test_promote_and_verify_round_trip(self, real_bundle_and_runner):
        build_dir, artifact, runner = real_bundle_and_runner
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=True),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="", exit_code=0),
        )
        entry = promote_to_regression_suite(
            artifact, expectation, suite_root=build_dir / "suite"
        )
        input_bytes = (
            build_dir / "suite" / "auto_generated" / entry.input_path
        ).read_bytes()
        assert input_bytes == b"PWN"

        report = verify_manifest_entry(runner, entry, input_bytes)
        assert report.ok is True
        assert report.base.crashed and report.base.ok
        assert not report.patched.crashed and report.patched.ok

    def test_patched_regression_detected(self, real_bundle_and_runner):

        build_dir, artifact, runner = real_bundle_and_runner
        runner._binaries["patched"] = runner._binaries["base"]
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=True),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="", exit_code=0),
        )
        entry = promote_to_regression_suite(
            artifact, expectation, suite_root=build_dir / "suite2"
        )
        input_bytes = (
            build_dir / "suite2" / "auto_generated" / entry.input_path
        ).read_bytes()
        report = verify_manifest_entry(runner, entry, input_bytes)
        assert report.ok is False
        assert report.base.ok is True
        assert report.patched.ok is False
        assert "clean exit was expected" in report.patched.reason


class TestInputIntegrity:
    def test_hash_mismatch_rejected_with_zero_runner_calls(self, tmp_path):
        artifact = write_bundle(tmp_path)
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        with pytest.raises(RegressionError, match="integrity check failed"):
            verify_manifest_entry(runner, entry, b"WRONG")
        assert runner.calls == []

    def test_matching_input_verifies_with_calls(self, tmp_path):
        artifact = write_bundle(tmp_path)
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        report = verify_manifest_entry(runner, entry, b"PWN")
        assert report.ok is True
        assert [call[1] for call in runner.calls] == ["base", "patched"]


class TestBundleBinding:
    def test_foreign_input_path_rejected(self, tmp_path):
        artifact = write_bundle(tmp_path)
        foreign = tmp_path / "unrelated.bin"
        foreign.write_bytes(b"PWN")
        artifact.minimized_input_path = str(foreign)
        with pytest.raises(RegressionError, match="does not resolve"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()

    def test_symlink_escape_rejected(self, tmp_path):
        artifact = write_bundle(tmp_path)
        outside = tmp_path / "outside.bin"
        outside.write_bytes(b"PWN")
        link = tmp_path / "reproducers" / "f1" / "minimized_input.bin"
        link.unlink()
        os.symlink(outside, link)
        with pytest.raises(RegressionError, match="regular, non-symlink"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()

    def test_symlink_to_same_sized_file_inside_bundle_rejected(self, tmp_path):

        artifact = write_bundle(tmp_path, minimized=b"XXXX")
        decoy = tmp_path / "reproducers" / "f1" / "decoy.bin"
        decoy.write_bytes(b"YYYY")
        link = tmp_path / "reproducers" / "f1" / "minimized_input.bin"
        link.unlink()
        os.symlink(decoy, link)
        with pytest.raises(RegressionError, match="regular, non-symlink"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()

    def test_dangling_symlink_rejected(self, tmp_path):
        artifact = write_bundle(tmp_path)
        link = tmp_path / "reproducers" / "f1" / "minimized_input.bin"
        link.unlink()
        os.symlink(tmp_path / "does_not_exist.bin", link)
        with pytest.raises(RegressionError, match="regular, non-symlink"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()

    def test_normal_minimized_input_still_promotes(self, tmp_path):
        artifact = write_bundle(tmp_path)
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        assert entry.finding_id == "f1"
        assert (
            tmp_path / "suite" / "auto_generated" / entry.input_path
        ).read_bytes() == b"PWN"

    def test_symlinked_bundle_directory_still_promotes(self, tmp_path):

        artifact = write_bundle(tmp_path)
        real_root = tmp_path / "real_reproducers"
        (tmp_path / "reproducers").rename(real_root)
        os.symlink(real_root, tmp_path / "reproducers")
        artifact.bundle_dir = str(tmp_path / "reproducers" / "f1")
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        assert entry.finding_id == "f1"

    def test_metadata_finding_id_mismatch_rejected(self, tmp_path):
        artifact = write_bundle(tmp_path)
        metadata_path = tmp_path / "reproducers" / "f1" / "metadata.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["finding_id"] = "other"
        metadata_path.write_text(json.dumps(metadata))
        with pytest.raises(RegressionError, match="finding ID mismatch"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_bundle_dir_name_mismatch_rejected(self, tmp_path):
        artifact = write_bundle(tmp_path)
        renamed = tmp_path / "reproducers" / "other"
        renamed.mkdir()
        (renamed / "metadata.json").write_bytes(
            (tmp_path / "reproducers" / "f1" / "metadata.json").read_bytes()
        )
        artifact.bundle_dir = str(renamed)
        with pytest.raises(RegressionError, match="does not match"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    @pytest.mark.parametrize(
        "tamper",
        [
            "artifact_min_size",
            "artifact_original_size",
            "metadata_min_size",
            "actual_min_file",
            "bool_size",
        ],
    )
    def test_size_mismatches_rejected(self, tmp_path, tamper):
        artifact = write_bundle(tmp_path, input_bytes=b"AAA", minimized=b"PWN")
        metadata_path = tmp_path / "reproducers" / "f1" / "metadata.json"
        if tamper == "artifact_min_size":
            artifact.minimized_size_bytes = 999
        elif tamper == "artifact_original_size":
            artifact.original_size_bytes = 999
        elif tamper == "metadata_min_size":
            metadata = json.loads(metadata_path.read_text())
            metadata["minimization"]["minimized_size_bytes"] = 999
            metadata_path.write_text(json.dumps(metadata))
        elif tamper == "actual_min_file":
            (tmp_path / "reproducers" / "f1" / "minimized_input.bin").write_bytes(
                b"PWNX"
            )
        elif tamper == "bool_size":
            artifact.minimized_size_bytes = True
        with pytest.raises(RegressionError, match="size mismatch"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()


def make_entry(expected: dict, **overrides) -> ManifestEntry:
    kwargs = dict(
        finding_id="f1",
        input_path="f1_minimized_abc.bin",
        input_sha256=hashlib.sha256(b"PWN").hexdigest(),
        source_bundle="reproducers/f1",
        build_type="sanitized",
        compile_flags=None,
        commit={"base": None, "patched": None},
        input_mode="stdin",
        argv_template=[],
        expected=expected,
        created_at="2026-11-13T00:00:00+00:00",
    )
    kwargs.update(overrides)
    return ManifestEntry(**kwargs)


GOOD_BASE = {
    "crash": True,
    "signature": {
        "error_type": "heap-buffer-overflow",
        "function": "copy_data",
        "file": "src/parse.c",
        "line": 42,
    },
    "test_id": "t1",
}
GOOD_PATCHED = {"crash": False, "exit_code": 0, "test_id": "t1",
                "oracle": {"stdout_kind": "exact", "stdout_value": "ok", "stderr_pattern": None}}


class TestStrictExpectationValidation:
    @pytest.mark.parametrize(
        "base_expected,match",
        [
            ({"crash": "false", "exit_code": 0}, "actual boolean"),
            ({"crash": "true", "exit_code": 0}, "actual boolean"),
            ({"crash": 1, "exit_code": 0}, "actual boolean"),
            ({"crash": 0, "exit_code": 0}, "actual boolean"),
            ({"crash": False}, "requires an explicit exit_code"),
            ({"exit_code": 0}, "missing the required 'crash' field"),
            ({}, "missing the required 'crash' field"),
            ({"crash": True}, "requires a resolved signature"),
            ({"crash": True, "signature": {}}, "insufficient evidence"),
        ],
    )
    def test_invalid_manifest_expectations_rejected_with_zero_calls(
        self, base_expected, match
    ):
        entry = make_entry({"base": base_expected, "patched": GOOD_PATCHED})
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        with pytest.raises(RegressionError, match=match):
            verify_manifest_entry(runner, entry, b"PWN")
        assert runner.calls == []

    @pytest.mark.parametrize(
        "patched_expected,match",
        [
            ({"crash": False, "exit_code": True}, "integer"),
            ({"crash": False, "exit_code": "3"}, "integer"),
            ({"crash": "false", "exit_code": 0}, "actual boolean"),
        ],
    )
    def test_invalid_patched_expectations_rejected(self, patched_expected, match):
        entry = make_entry({"base": GOOD_BASE, "patched": patched_expected})
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched")
        )
        with pytest.raises(RegressionError, match=match):
            verify_manifest_entry(runner, entry, b"PWN")
        assert runner.calls == []

    def test_malformed_expected_structure_rejected(self):
        for expected in (None, [], "base", {"base": "not-a-dict"}):
            entry = make_entry(expected)
            runner = VersionedRunner(
                base=make_crash(), patched=make_clean(version="patched")
            )
            with pytest.raises(RegressionError, match="malformed"):
                verify_manifest_entry(runner, entry, b"PWN")
            assert runner.calls == []

    def test_unsupported_manifest_format_rejected_without_changes(self, tmp_path):
        artifact = write_bundle(tmp_path)
        promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        manifest_path = tmp_path / "suite" / "auto_generated" / "manifest.json"
        before = manifest_path.read_bytes()
        original = json.loads(before)
        original["format"] = 999
        manifest_path.write_text(json.dumps(original))
        other = write_bundle(tmp_path, finding_id="f2", minimized=b"BBB")
        with pytest.raises(RegressionError, match="unsupported manifest format"):
            promote_to_regression_suite(
                other, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

        assert manifest_path.read_bytes() == json.dumps(original).encode()

    def test_api_path_rejects_non_bool_crash(self, tmp_path):
        artifact = write_bundle(tmp_path)
        expectation = RegressionExpectation(
            base=VersionExpectation(crash="false"),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=0),
        )
        with pytest.raises(RegressionError, match="actual boolean"):
            promote_to_regression_suite(
                artifact, expectation, suite_root=tmp_path / "suite"
            )

    def test_api_path_rejects_boolean_exit_code(self, tmp_path):
        artifact = write_bundle(tmp_path)
        expectation = RegressionExpectation(
            base=VersionExpectation(crash=True),
            patched=VersionExpectation(crash=False, stdout_kind="exact", stdout_value="ok", exit_code=True),
        )
        with pytest.raises(RegressionError, match="integer"):
            promote_to_regression_suite(
                artifact, expectation, suite_root=tmp_path / "suite"
            )

    def test_valid_nonzero_exit_code_from_manifest_still_supported(self):
        entry = make_entry(
            {
                "base": GOOD_BASE,
                "patched": {"crash": False, "exit_code": 3, "test_id": "t1", "oracle": {"stdout_kind": "exact", "stdout_value": "ok"}},
            }
        )
        runner = VersionedRunner(
            base=make_crash(), patched=make_clean(version="patched", exit_code=3)
        )
        assert verify_manifest_entry(runner, entry, b"PWN").ok is True


class TestReplayEvidence:
    @pytest.mark.parametrize(
        "replay,match",
        [
            (
                _with_provenance(
                    {
                        "total": 0,
                        "matching": 0,
                        "deterministic": True,
                        "is_flaky": False,
                        "results": [],
                    }
                ),
                "positive integer",
            ),
            (
                _with_provenance(
                    {
                        "total": 3,
                        "matching": True,
                        "deterministic": True,
                        "is_flaky": False,
                        "results": [],
                    }
                ),
                "positive integer",
            ),
            (
                _with_provenance(
                    {
                        "total": -1,
                        "matching": -1,
                        "deterministic": True,
                        "is_flaky": False,
                        "results": [],
                    }
                ),
                "positive integer",
            ),
            (
                _with_provenance(
                    {
                        "total": 3,
                        "matching": 2,
                        "deterministic": True,
                        "is_flaky": False,
                        "results": [],
                    }
                ),
                "inconsistent",
            ),
            (
                _with_provenance(
                    {
                        "total": 3,
                        "matching": 3,
                        "deterministic": False,
                        "is_flaky": False,
                        "results": [],
                    }
                ),
                "exactly True",
            ),
            (
                _with_provenance(
                    {
                        "total": 3,
                        "matching": 3,
                        "deterministic": "yes",
                        "is_flaky": False,
                        "results": [],
                    }
                ),
                "exactly True",
            ),
            (
                _with_provenance(
                    {
                        "total": 3,
                        "matching": 3,
                        "deterministic": True,
                        "is_flaky": 0,
                        "results": [],
                    }
                ),
                "exactly False",
            ),
        ],
    )
    def test_invalid_counts_and_flags_rejected(self, tmp_path, replay, match):
        artifact = write_bundle(tmp_path, replay=replay)
        with pytest.raises(RegressionError, match=match):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()

    def test_missing_results_rejected(self, tmp_path):
        replay = _with_provenance(
            {"total": 3, "matching": 3, "deterministic": True, "is_flaky": False}
        )
        artifact = write_bundle(tmp_path, replay=replay)
        with pytest.raises(RegressionError, match="exactly 3 replay records"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_wrong_record_count_rejected(self, tmp_path):
        replay = _with_provenance(
            {
                "total": 3,
                "matching": 3,
                "deterministic": True,
                "is_flaky": False,
                "results": [_record(1), _record(2)],
            }
        )
        artifact = write_bundle(tmp_path, replay=replay)
        with pytest.raises(RegressionError, match="exactly 3 replay records"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    @pytest.mark.parametrize(
        "records,match",
        [
            ([_record(1), _record(1), _record(2)], "duplicate"),
            ([_record(1), _record(2), _record(4)], "invalid attempt"),
            ([_record(1), _record(2), _record(True)], "invalid attempt"),
            ([_record(1), _record(2), _record(3, matched=False)], "matched=True"),
            ([_record(1), _record(2), _record(3, crashed=False)], "crashed=True"),
            ([_record(1), _record(2), _record(3, timed_out=True)], "timed out"),
            ([_record(1), _record(2), _record(3, oom_killed=True)], "OOM-killed"),
            (
                [
                    _record(1),
                    _record(2),
                    _record(
                        3,
                        signature=[
                            "heap-buffer-overflow",
                            "copy_data",
                            "src/parse.c",
                            99,
                        ],
                    ),
                ],
                "not strictly consistent",
            ),
            (
                [_record(1), _record(2), _record(3, signature=None)],
                "not strictly consistent",
            ),
            (
                [
                    _record(1),
                    _record(2),
                    _record(3, signature=[None, None, None, None]),
                ],
                "not strictly consistent",
            ),
        ],
    )
    def test_invalid_records_rejected(self, tmp_path, records, match):
        replay = _with_provenance(
            {
                "total": 3,
                "matching": 3,
                "deterministic": True,
                "is_flaky": False,
                "results": records,
            }
        )
        artifact = write_bundle(tmp_path, replay=replay)
        with pytest.raises(RegressionError, match=match):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()

    def test_configurable_replay_count_succeeds(self, tmp_path):

        replay = _with_provenance(
            {
                "total": 5,
                "matching": 5,
                "deterministic": True,
                "is_flaky": False,
                "results": _replay_results(_default_crash(), 5),
            }
        )
        artifact = write_bundle(tmp_path, replay=replay)
        entry = promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        assert artifact.deterministic_replays == "5/5"
        assert entry.finding_id == "f1"

    def test_missing_provenance_rejected_conservatively(self, tmp_path):

        replay = {
            "total": 3,
            "matching": 3,
            "deterministic": True,
            "is_flaky": False,
            "results": _replay_results(_default_crash(), 3),
        }
        artifact = write_bundle(tmp_path, replay=replay)
        with pytest.raises(RegressionError, match="missing execution provenance"):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )
        assert not (tmp_path / "suite" / "auto_generated").exists()

    def test_provenance_version_mismatch_rejected(self, tmp_path):
        replay = _with_provenance(
            {
                "total": 3,
                "matching": 3,
                "deterministic": True,
                "is_flaky": False,
                "results": _replay_results(_default_crash(), 3),
            },
            version="patched",
        )
        artifact = write_bundle(tmp_path, replay=replay)
        with pytest.raises(
            RegressionError, match="does not match the bundle crash version"
        ):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )

    def test_provenance_build_type_mismatch_rejected(self, tmp_path):
        replay = _with_provenance(
            {
                "total": 3,
                "matching": 3,
                "deterministic": True,
                "is_flaky": False,
                "results": _replay_results(_default_crash(), 3),
            },
            build_type="release",
        )
        artifact = write_bundle(tmp_path, replay=replay)
        with pytest.raises(
            RegressionError, match="does not match the bundle build type"
        ):
            promote_to_regression_suite(
                artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
            )


class TestPublicationConsistency:
    def test_failed_manifest_publish_keeps_old_suite_usable(
        self, tmp_path, monkeypatch
    ):
        artifact = write_bundle(tmp_path, minimized=b"AAA")
        promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )

        real_write = generator_module._atomic_write

        def flaky_write(path, data):
            if path.name == "manifest.json":
                raise OSError("disk full")
            real_write(path, data)

        monkeypatch.setattr(generator_module, "_atomic_write", flaky_write)
        changed = write_bundle(tmp_path, minimized=b"BBB")
        with pytest.raises(OSError, match="disk full"):
            promote_to_regression_suite(
                changed,
                DEFAULT_EXPECTATION,
                suite_root=tmp_path / "suite",
                replace=True,
            )

        manifest = read_manifest(tmp_path / "suite")
        auto = tmp_path / "suite" / "auto_generated"
        for entry in manifest["entries"].values():
            path = auto / entry["input_path"]
            assert path.is_file()
            assert path.read_bytes() == b"AAA"
            assert (
                hashlib.sha256(path.read_bytes()).hexdigest() == entry["input_sha256"]
            )

    def test_successful_replace_publishes_new_input(self, tmp_path):
        artifact = write_bundle(tmp_path, minimized=b"AAA")
        promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        changed = write_bundle(tmp_path, minimized=b"BBB")
        entry = promote_to_regression_suite(
            changed,
            DEFAULT_EXPECTATION,
            suite_root=tmp_path / "suite",
            replace=True,
        )
        auto = tmp_path / "suite" / "auto_generated"
        assert entry.input_path == _vname("f1", b"BBB")
        assert (auto / entry.input_path).read_bytes() == b"BBB"

        assert (auto / _vname("f1", b"AAA")).read_bytes() == b"AAA"

    def test_idempotent_repromotion_writes_no_new_files(self, tmp_path):
        artifact = write_bundle(tmp_path)
        promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        auto = tmp_path / "suite" / "auto_generated"
        before = sorted(p.name for p in auto.iterdir())
        promote_to_regression_suite(
            artifact, DEFAULT_EXPECTATION, suite_root=tmp_path / "suite"
        )
        after = sorted(p.name for p in auto.iterdir())
        assert after == before
        assert before == sorted([_vname("f1", b"PWN"), "manifest.json"])
