from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from models import (
    CrashSignature,
    ExecutionResult,
    ReproducerArtifact,
    RunnerPort,
    StackFrame,
    assert_execution_context,
    crash_signature,
    strict_crash_match,
    sufficient_crash_evidence,
)
from reproducer.bundler import _FINDING_ID_RE, DEFAULT_TIMEOUT_SEC
from oracle.functional_oracle import OracleExpectation, evaluate

MANIFEST_FORMAT = 2
AUTO_GENERATED_DIR = "auto_generated"
MANIFEST_NAME = "manifest.json"


class RegressionError(Exception):
    pass


@dataclass
class VersionExpectation:
    crash: bool = False
    exit_code: int | None = None
    signature: CrashSignature | None = None
    test_id: str | None = None
    stdout_kind: str | None = None
    stdout_value: object = None
    stderr_pattern: str | None = None

    def to_dict(self) -> dict:
        data: dict = {"crash": self.crash}
        if self.crash and self.signature is not None:
            data["signature"] = self.signature._asdict()
        if self.exit_code is not None:
            data["exit_code"] = self.exit_code
        if self.test_id is not None:
            data["test_id"] = self.test_id
        if not self.crash:
            data["oracle"] = {
                "stdout_kind": self.stdout_kind,
                "stdout_value": self.stdout_value,
                "stderr_pattern": self.stderr_pattern,
            }
        return data

    def validate(self, label: str, *, allow_unresolved_signature: bool) -> None:

        if not isinstance(self.crash, bool):
            raise RegressionError(
                f"{label}: crash must be an actual boolean, got {self.crash!r}"
            )
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise RegressionError(
                f"{label}: exit_code must be an integer (booleans rejected), "
                f"got {self.exit_code!r}"
            )
        if self.test_id is not None and (
            not isinstance(self.test_id, str) or not self.test_id
        ):
            raise RegressionError(
                f"{label}: test_id must be a non-empty string when supplied, "
                f"got {self.test_id!r}"
            )
        if not self.crash:
            if self.exit_code is None:
                raise RegressionError(
                    f"{label}: clean-run expectation requires an explicit "
                    "exit_code (nonzero allowed)"
                )
            if self.stdout_kind not in ("exact", "regex", "json"):
                raise RegressionError(f"{label}: clean-run expectation requires an independent stdout oracle")
            if self.stdout_kind in ("exact", "regex") and not isinstance(self.stdout_value, str):
                raise RegressionError(f"{label}: stdout oracle value must be a string")
            try:
                if self.stdout_kind == "regex":
                    re.compile(self.stdout_value)
                if self.stdout_kind == "json":
                    json.dumps(self.stdout_value, allow_nan=False)
                if self.stderr_pattern is not None:
                    if not isinstance(self.stderr_pattern, str):
                        raise TypeError("stderr_pattern must be a string")
                    re.compile(self.stderr_pattern)
            except (ValueError, TypeError, re.error) as exc:
                raise RegressionError(f"{label}: invalid independent oracle: {exc}") from exc
        elif self.signature is None:
            if not allow_unresolved_signature:
                raise RegressionError(
                    f"{label}: crash expectation requires a resolved "
                    "signature (no bundle context available to derive one)"
                )
        elif not isinstance(self.signature, CrashSignature):
            raise RegressionError(
                f"{label}: signature must be a CrashSignature object, got "
                f"{type(self.signature).__name__} — the Python API performs "
                "no implicit conversion"
            )
        elif not sufficient_crash_evidence(self.signature):
            raise RegressionError(
                f"{label}: crash expectation has insufficient evidence "
                f"(need an error type and a top frame): {_sig_str(self.signature)}"
            )


@dataclass
class RegressionExpectation:
    base: VersionExpectation
    patched: VersionExpectation

    def validate(self, *, bundle_signature: CrashSignature) -> None:
        self.base.validate("base", allow_unresolved_signature=True)
        self.patched.validate("patched", allow_unresolved_signature=True)
        crashes_expected = False
        for label, expectation in (("base", self.base), ("patched", self.patched)):
            if expectation.crash:
                crashes_expected = True
                effective = expectation.signature or bundle_signature
                if not sufficient_crash_evidence(effective):
                    raise RegressionError(
                        f"{label}: crash expectation has insufficient evidence "
                        "(need an error type and a top frame) — neither the "
                        "bundle nor an explicit override provides it"
                    )
        if not crashes_expected:
            raise RegressionError(
                "at least one version must expect a crash; a regression entry "
                "promoted from a crash finding cannot be all-clean"
            )


@dataclass
class ManifestEntry:
    finding_id: str
    input_path: str
    input_sha256: str
    source_bundle: str
    build_type: str
    compile_flags: str | None
    commit: dict
    input_mode: str
    argv_template: list[str]
    expected: dict
    created_at: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ManifestEntry":
        return cls(**data)


def promote_to_regression_suite(
    artifact: ReproducerArtifact,
    expectation: RegressionExpectation,
    *,
    suite_root: str | Path,
    replace: bool = False,
) -> ManifestEntry:

    _validate_finding_id(artifact.finding_id)

    if artifact.is_flaky:
        raise RegressionError(
            f"finding {artifact.finding_id}: artifact is inconclusive "
            f"(is_flaky=True, deterministic_replays={artifact.deterministic_replays!r}); "
            "refusing to promote"
        )

    bundle_dir = Path(artifact.bundle_dir)
    metadata = _load_bundle_metadata(bundle_dir)
    if metadata.get("finding_id") != artifact.finding_id:
        raise RegressionError(
            f"finding ID mismatch: artifact {artifact.finding_id!r} vs bundle "
            f"metadata {metadata.get('finding_id')!r}"
        )
    if bundle_dir.name != artifact.finding_id:
        raise RegressionError(
            f"bundle directory name {bundle_dir.name!r} does not match "
            f"finding ID {artifact.finding_id!r}"
        )
    minimization = metadata.get("minimization")
    if not isinstance(minimization, dict):
        raise RegressionError(
            f"bundle metadata for {artifact.finding_id} is "
            "missing the 'minimization' section"
        )
    if minimization.get("skipped") is not False:
        raise RegressionError(
            f"finding {artifact.finding_id}: minimization was skipped "
            f"(reason: {minimization.get('skip_reason')!r}); refusing to promote"
        )
    if minimization.get("revalidated") is not True:
        raise RegressionError(
            f"finding {artifact.finding_id}: minimized input was not "
            "revalidated; refusing to promote"
        )

    bundle_signature = _crash_signature_from_metadata(metadata)
    if not sufficient_crash_evidence(bundle_signature):
        raise RegressionError(
            f"finding {artifact.finding_id}: bundle crash evidence is "
            "insufficient (need an error type and a top frame) — replay "
            "evidence cannot be validated and no expected signature can be "
            "derived"
        )
    _validate_replay_evidence(metadata, artifact, bundle_signature)

    minimized_path = Path(artifact.minimized_input_path)

    if minimized_path.is_symlink():
        raise RegressionError(
            f"finding {artifact.finding_id}: minimized input "
            f"{artifact.minimized_input_path!r} is a symlink — the minimized "
            "input must be a regular, non-symlink file"
        )

    if (
        minimized_path.name != "minimized_input.bin"
        or minimized_path.resolve().parent != bundle_dir.resolve()
    ):
        raise RegressionError(
            f"finding {artifact.finding_id}: minimized input path "
            f"{artifact.minimized_input_path!r} does not resolve to the "
            f"bundle's minimized_input.bin — foreign paths and symlink "
            "escapes are rejected"
        )
    if not minimized_path.is_file():
        raise RegressionError(
            f"finding {artifact.finding_id}: minimized input not found: "
            f"{minimized_path}"
        )
    _validate_sizes(artifact, bundle_dir, minimization, minimized_path)
    input_bytes = minimized_path.read_bytes()

    expectation.validate(bundle_signature=bundle_signature)
    replay_test_id = (metadata.get("replay") or {}).get("test_id")
    resolved_expectation = RegressionExpectation(
        base=_resolve_context(expectation.base, bundle_signature, replay_test_id),
        patched=_resolve_context(expectation.patched, bundle_signature, replay_test_id),
    )
    input_rel = _versioned_input_name(artifact.finding_id, input_bytes)
    entry = _build_entry(
        artifact, input_bytes, input_rel, metadata, resolved_expectation
    )

    auto_dir = Path(suite_root) / AUTO_GENERATED_DIR
    manifest_path = auto_dir / MANIFEST_NAME
    manifest = _load_manifest(manifest_path)
    existing = manifest["entries"].get(artifact.finding_id)
    new_input_path = auto_dir / entry.input_path

    if existing is not None:
        if _entries_equivalent(existing, entry) and _file_matches(
            new_input_path, input_bytes
        ):
            return ManifestEntry.from_dict(existing)
        if not replace:
            raise RegressionError(
                f"finding {artifact.finding_id}: a conflicting entry already "
                "exists in the manifest; pass replace=True to overwrite it"
            )

    try:
        auto_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RegressionError(f"cannot create suite dir {auto_dir}: {exc}") from exc

    _atomic_write(new_input_path, input_bytes)

    published = dict(manifest)
    published["entries"][artifact.finding_id] = entry.to_dict()
    _atomic_write(manifest_path, json.dumps(published, indent=2, sort_keys=True) + "\n")
    return entry


@dataclass
class VersionOutcome:
    version: str
    crashed: bool
    exit_code: int
    error_type: str | None
    signature: CrashSignature
    timed_out: bool
    oom_killed: bool
    ok: bool
    reason: str


@dataclass
class VerificationReport:
    base: VersionOutcome
    patched: VersionOutcome

    @property
    def ok(self) -> bool:
        return self.base.ok and self.patched.ok


def verify_regression(
    runner: RunnerPort,
    input_bytes: bytes,
    expectation: RegressionExpectation,
    *,
    build_type: str,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
) -> VerificationReport:

    if not isinstance(expectation, RegressionExpectation):
        raise RegressionError(
            f"expectation must be a RegressionExpectation, got "
            f"{type(expectation).__name__}"
        )
    for label, version_expectation in (
        ("base", getattr(expectation, "base", None)),
        ("patched", getattr(expectation, "patched", None)),
    ):
        if not isinstance(version_expectation, VersionExpectation):
            raise RegressionError(
                f"expectation.{label} must be a VersionExpectation object, "
                f"got {type(version_expectation).__name__}"
            )
    expectation.base.validate("base", allow_unresolved_signature=False)
    expectation.patched.validate("patched", allow_unresolved_signature=False)
    for label, version_expectation in (
        ("base", expectation.base),
        ("patched", expectation.patched),
    ):
        if not version_expectation.test_id:
            raise RegressionError(
                f"{label}: missing expected test provenance (test_id) — "
                "legacy expectations without provenance are rejected before "
                "any execution; never inferred from returned results. "
                "Obtain a real ExecutionResult from the target context and "
                "re-promote to record it."
            )
    base_result = runner.run(
        input_bytes, version="base", build_type=build_type, timeout_sec=timeout_sec
    )
    assert_execution_context(base_result, version="base", build_type=build_type)
    if expectation.base.test_id is not None:
        assert_execution_context(base_result, test_id=expectation.base.test_id)
    patched_result = runner.run(
        input_bytes, version="patched", build_type=build_type, timeout_sec=timeout_sec
    )
    assert_execution_context(patched_result, version="patched", build_type=build_type)
    if expectation.patched.test_id is not None:
        assert_execution_context(patched_result, test_id=expectation.patched.test_id)
    return VerificationReport(
        base=_evaluate(base_result, expectation.base),
        patched=_evaluate(patched_result, expectation.patched),
    )


def load_regression_suite(suite_root: str | Path) -> list[tuple[ManifestEntry, bytes]]:
    directory = Path(suite_root) / AUTO_GENERATED_DIR
    manifest = _load_manifest(directory / MANIFEST_NAME)
    entries = []
    for finding_id, row in manifest["entries"].items():
        _validate_finding_id(finding_id)
        try:
            entry = ManifestEntry.from_dict(row)
        except (TypeError, ValueError) as exc:
            raise RegressionError(f"invalid saved regression {finding_id}: {exc}") from exc
        if entry.finding_id != finding_id:
            raise RegressionError(f"saved regression key does not match finding ID: {finding_id}")
        if not isinstance(entry.input_path, str) or Path(entry.input_path).name != entry.input_path:
            raise RegressionError(f"invalid saved regression input path: {finding_id}")
        path = directory / entry.input_path
        if path.is_symlink() or not path.is_file():
            raise RegressionError(f"saved regression input must be a regular non-symlink file: {path}")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != entry.input_sha256:
            raise RegressionError(f"saved regression input integrity check failed: {finding_id}")
        entries.append((entry, content))
    return entries


def verify_manifest_entry(
    runner: RunnerPort,
    entry: ManifestEntry,
    input_bytes: bytes,
    *,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
) -> VerificationReport:

    actual_sha256 = hashlib.sha256(input_bytes).hexdigest()
    expected = entry.expected
    if (
        not isinstance(expected, dict)
        or not isinstance(expected.get("base"), dict)
        or not isinstance(expected.get("patched"), dict)
    ):
        raise RegressionError(
            f"manifest entry for {entry.finding_id} has a malformed "
            "'expected' structure (need objects for 'base' and 'patched')"
        )
    if actual_sha256 != entry.input_sha256:
        raise RegressionError(
            f"input integrity check failed for {entry.finding_id}: sha256 "
            f"{actual_sha256} does not match manifest entry {entry.input_sha256}"
        )
    return verify_regression(
        runner,
        input_bytes,
        RegressionExpectation(
            base=_expectation_from_dict(entry.expected["base"]),
            patched=_expectation_from_dict(entry.expected["patched"]),
        ),
        build_type=entry.build_type,
        timeout_sec=timeout_sec,
    )


def _evaluate(
    result: ExecutionResult, expectation: VersionExpectation
) -> VersionOutcome:
    if expectation.crash:
        expected_signature = expectation.signature
        if expected_signature is None:
            raise RegressionError("crash expectation requires a resolved signature")
        if not sufficient_crash_evidence(expected_signature):
            raise RegressionError(
                f"expected crash signature has insufficient evidence: "
                f"{_sig_str(expected_signature)}"
            )
        if result.timed_out:
            ok, reason = False, "timed out — cannot satisfy a crash expectation"
        elif result.oom_killed:
            ok, reason = False, "OOM-killed — cannot satisfy a crash expectation"
        elif strict_crash_match(result, expected_signature):
            ok, reason = (
                True,
                (
                    f"crash signature matched ({result.error_type} @ "
                    f"{_sig_str(crash_signature(result))})"
                ),
            )
        else:
            ok, reason = (
                False,
                (
                    f"crash signature mismatch: expected {_sig_str(expected_signature)}, "
                    f"got {_sig_str(crash_signature(result))}"
                ),
            )
        if (
            ok
            and expectation.exit_code is not None
            and result.exit_code != expectation.exit_code
        ):
            ok, reason = (
                False,
                (
                    f"crash matched but exit_code {result.exit_code} != expected "
                    f"{expectation.exit_code}"
                ),
            )
    else:
        if result.crashed:
            ok, reason = (
                False,
                (
                    f"crashed ({result.error_type or 'unclassified'}) but a clean "
                    f"exit was expected"
                ),
            )
        elif result.timed_out:
            ok, reason = False, "timed out — cannot satisfy a clean-run expectation"
        elif result.oom_killed:
            ok, reason = False, "OOM-killed — cannot satisfy a clean-run expectation"
        elif result.exit_code != expectation.exit_code:
            ok, reason = (
                False,
                (f"exit_code {result.exit_code} != expected {expectation.exit_code}"),
            )
        else:
            oracle = evaluate(result, OracleExpectation(
                result.test_id, expectation.exit_code, False,
                expectation.stdout_kind, expectation.stdout_value, expectation.stderr_pattern,
            ))
            ok = oracle.passed
            reason = "independent oracle satisfied; exit_code as expected" if ok else "; ".join(oracle.reasons)

    return VersionOutcome(
        version=result.version,
        crashed=result.crashed,
        exit_code=result.exit_code,
        error_type=result.error_type,
        signature=crash_signature(result),
        timed_out=result.timed_out,
        oom_killed=result.oom_killed,
        ok=ok,
        reason=reason,
    )


def _validate_finding_id(finding_id: str) -> None:
    if not _FINDING_ID_RE.fullmatch(finding_id):
        raise RegressionError(
            f"invalid finding_id {finding_id!r}: use only letters, digits, '.', "
            "'_', '-' (no path separators)"
        )


def _load_bundle_metadata(bundle_dir: Path) -> dict:
    path = bundle_dir / "metadata.json"
    if not path.is_file():
        raise RegressionError(f"bundle metadata not found: {path}")
    try:
        metadata = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise RegressionError(f"bundle metadata corrupted: {path}") from exc
    if not isinstance(metadata, dict):
        raise RegressionError(f"bundle metadata has unexpected structure: {path}")
    return metadata


def _validate_replay_evidence(
    metadata: dict, artifact: ReproducerArtifact, original: CrashSignature
) -> None:

    finding_id = artifact.finding_id
    replay = metadata.get("replay")
    if not isinstance(replay, dict):
        raise RegressionError(
            f"bundle metadata for {finding_id} is missing the 'replay' section"
        )

    test_id = replay.get("test_id")
    version = replay.get("version")
    build_type = replay.get("build_type")
    if not test_id or not version or not build_type:
        raise RegressionError(
            f"finding {finding_id}: replay evidence is missing execution "
            "provenance (test_id/version/build_type); bundles without "
            "provenance are rejected conservatively"
        )
    crash = metadata.get("crash") or {}
    if version != crash.get("version"):
        raise RegressionError(
            f"finding {finding_id}: replay provenance version {version!r} "
            f"does not match the bundle crash version {crash.get('version')!r}"
        )
    build = metadata.get("build") or {}
    if build_type != build.get("build_type"):
        raise RegressionError(
            f"finding {finding_id}: replay provenance build_type "
            f"{build_type!r} does not match the bundle build type "
            f"{build.get('build_type')!r}"
        )
    total = replay.get("total")
    matching = replay.get("matching")
    for label, value in (("total", total), ("matching", matching)):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise RegressionError(
                f"finding {finding_id}: replay {label} must be a positive "
                f"integer, got {value!r}"
            )
    if matching != total:
        raise RegressionError(
            f"finding {finding_id}: replay evidence inconsistent "
            f"({matching}/{total} matching)"
        )
    if replay.get("deterministic") is not True:
        raise RegressionError(
            f"finding {finding_id}: replay deterministic must be exactly "
            f"True, got {replay.get('deterministic')!r}"
        )
    if replay.get("is_flaky") is not False:
        raise RegressionError(
            f"finding {finding_id}: replay is_flaky must be exactly False, "
            f"got {replay.get('is_flaky')!r}"
        )
    if f"{matching}/{total}" != artifact.deterministic_replays:
        raise RegressionError(
            f"finding {finding_id}: artifact reports "
            f"deterministic_replays={artifact.deterministic_replays!r} but "
            f"bundle metadata says {matching}/{total}"
        )

    results = replay.get("results")
    if not isinstance(results, list) or len(results) != total:
        raise RegressionError(
            f"finding {finding_id}: expected exactly {total} replay records, "
            f"got {len(results) if isinstance(results, list) else type(results).__name__}"
        )
    seen_attempts: set[int] = set()
    for index, record in enumerate(results):
        if not isinstance(record, dict):
            raise RegressionError(
                f"finding {finding_id}: replay record {index} is not an object"
            )
        attempt = record.get("attempt")
        if (
            isinstance(attempt, bool)
            or not isinstance(attempt, int)
            or not 1 <= attempt <= total
        ):
            raise RegressionError(
                f"finding {finding_id}: replay record {index} has invalid "
                f"attempt {attempt!r} (must be an integer in 1..{total})"
            )
        if attempt in seen_attempts:
            raise RegressionError(
                f"finding {finding_id}: duplicate replay attempt {attempt}"
            )
        seen_attempts.add(attempt)
        if record.get("crashed") is not True:
            raise RegressionError(
                f"finding {finding_id}: replay record {index} (attempt "
                f"{attempt}) must have crashed=True, got {record.get('crashed')!r}"
            )
        if record.get("timed_out") is not False:
            raise RegressionError(
                f"finding {finding_id}: replay record {index} (attempt "
                f"{attempt}) timed out — not a matching crash"
            )
        if record.get("oom_killed") is not False:
            raise RegressionError(
                f"finding {finding_id}: replay record {index} (attempt "
                f"{attempt}) was OOM-killed — not a matching crash"
            )
        if record.get("matched") is not True:
            raise RegressionError(
                f"finding {finding_id}: replay record {index} (attempt "
                f"{attempt}) must have matched=True, got {record.get('matched')!r}"
            )
        signature = _signature_from_json(record.get("signature"))
        synthetic = ExecutionResult(
            test_id=f"replay-{attempt}",
            version="base",
            build_type="",
            exit_code=0,
            crashed=True,
            timed_out=False,
            oom_killed=False,
            error_type=signature.error_type,
            stack_trace=(
                [
                    StackFrame(
                        index=0,
                        function=signature.function,
                        file=signature.file,
                        line=signature.line,
                    )
                ]
                if signature.function
                else []
            ),
        )
        if not strict_crash_match(synthetic, original):
            raise RegressionError(
                f"finding {finding_id}: replay record {index} (attempt "
                f"{attempt}) signature is not strictly consistent with the "
                f"original crash ({_sig_str(signature)} vs {_sig_str(original)})"
            )


def _validate_sizes(
    artifact: ReproducerArtifact,
    bundle_dir: Path,
    minimization: dict,
    minimized_path: Path,
) -> None:

    finding_id = artifact.finding_id
    crashing = bundle_dir / "crashing_input.bin"
    crashing_size = crashing.stat().st_size if crashing.is_file() else None
    minimized_size = minimized_path.stat().st_size
    checks = [
        (
            "crashing_input.bin",
            crashing_size,
            minimization.get("original_size_bytes"),
            "metadata minimization.original_size_bytes",
        ),
        (
            "crashing_input.bin",
            crashing_size,
            artifact.original_size_bytes,
            "artifact.original_size_bytes",
        ),
        (
            "minimized_input.bin",
            minimized_size,
            minimization.get("minimized_size_bytes"),
            "metadata minimization.minimized_size_bytes",
        ),
        (
            "minimized_input.bin",
            minimized_size,
            artifact.minimized_size_bytes,
            "artifact.minimized_size_bytes",
        ),
    ]
    for name, actual, expected, source in checks:
        if (
            isinstance(expected, bool)
            or not isinstance(expected, int)
            or expected < 0
            or actual != expected
        ):
            raise RegressionError(
                f"finding {finding_id}: size mismatch for {name}: actual "
                f"{actual} bytes vs {source}={expected!r}"
            )


def _signature_from_json(value) -> CrashSignature:

    if isinstance(value, list) and len(value) == 4:
        return CrashSignature(value[0], value[1], value[2], value[3])
    if isinstance(value, dict):
        return CrashSignature(
            value.get("error_type"),
            value.get("function"),
            value.get("file"),
            value.get("line"),
        )
    return CrashSignature(None, None, None, None)


def _versioned_input_name(finding_id: str, input_bytes: bytes) -> str:

    digest = hashlib.sha256(input_bytes).hexdigest()[:16]
    return f"{finding_id}_minimized_{digest}.bin"


def _file_matches(path: Path, expected_bytes: bytes) -> bool:
    if not path.is_file():
        return False
    return (
        hashlib.sha256(path.read_bytes()).digest()
        == hashlib.sha256(expected_bytes).digest()
    )


def _crash_signature_from_metadata(metadata: dict) -> CrashSignature:
    crash = metadata.get("crash") or {}
    top = crash.get("top_frame") or {}
    return CrashSignature(
        error_type=crash.get("error_type"),
        function=top.get("function"),
        file=top.get("file"),
        line=top.get("line"),
    )


def _resolve_context(
    expectation: VersionExpectation,
    bundle_signature: CrashSignature,
    replay_test_id: str | None,
) -> VersionExpectation:

    needs_signature = expectation.crash and expectation.signature is None
    needs_test_id = expectation.test_id is None and bool(replay_test_id)
    if not needs_signature and not needs_test_id:
        return expectation
    return VersionExpectation(
        crash=expectation.crash,
        exit_code=expectation.exit_code,
        signature=(bundle_signature if needs_signature else expectation.signature),
        test_id=replay_test_id if needs_test_id else expectation.test_id,
        stdout_kind=expectation.stdout_kind,
        stdout_value=expectation.stdout_value,
        stderr_pattern=expectation.stderr_pattern,
    )


def _build_entry(
    artifact: ReproducerArtifact,
    input_bytes: bytes,
    input_rel: str,
    metadata: dict,
    expectation: RegressionExpectation,
) -> ManifestEntry:
    build = metadata.get("build") or {}
    invocation = metadata.get("invocation") or {}
    return ManifestEntry(
        finding_id=artifact.finding_id,
        input_path=input_rel,
        input_sha256=hashlib.sha256(input_bytes).hexdigest(),
        source_bundle=str(artifact.bundle_dir),
        build_type=build.get("build_type", ""),
        compile_flags=build.get("compile_flags"),
        commit=dict(metadata.get("commit") or {"base": None, "patched": None}),
        input_mode=invocation.get("input_mode", ""),
        argv_template=list(invocation.get("argv_template") or []),
        expected={
            "base": expectation.base.to_dict(),
            "patched": expectation.patched.to_dict(),
        },
        created_at=datetime.now(timezone.utc).isoformat(),
    )


_IDEMPOTENT_FIELDS = (
    "finding_id",
    "input_path",
    "input_sha256",
    "build_type",
    "compile_flags",
    "commit",
    "input_mode",
    "argv_template",
    "expected",
)


def _entries_equivalent(existing: dict, entry: ManifestEntry) -> bool:
    new = entry.to_dict()
    return all(existing.get(key) == new[key] for key in _IDEMPOTENT_FIELDS)


def _load_manifest(manifest_path: Path) -> dict:
    if not manifest_path.exists():
        return {"format": MANIFEST_FORMAT, "entries": {}}
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:
        raise RegressionError(
            f"existing manifest is corrupted ({exc}); refusing to overwrite — "
            f"fix or remove {manifest_path}"
        ) from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("entries"), dict):
        raise RegressionError(
            f"existing manifest has unexpected structure; refusing to overwrite: "
            f"{manifest_path}"
        )
    if manifest.get("format") != MANIFEST_FORMAT:
        raise RegressionError(
            f"unsupported manifest format {manifest.get('format')!r} "
            f"(expected {MANIFEST_FORMAT}); refusing to touch {manifest_path}"
        )
    return manifest


def _atomic_write(path: Path, data: bytes | str) -> None:

    if isinstance(data, str):
        data = data.encode()
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _expectation_from_dict(data) -> VersionExpectation:

    if not isinstance(data, dict):
        raise RegressionError(
            f"expected an expectation object, got {type(data).__name__}"
        )
    if "crash" not in data:
        raise RegressionError("expectation is missing the required 'crash' field")
    signature_data = data.get("signature")
    oracle = data.get("oracle", {})
    if not isinstance(oracle, dict):
        raise RegressionError("expectation oracle must be an object")
    expectation = VersionExpectation(
        crash=data["crash"],
        exit_code=data.get("exit_code"),
        signature=(
            _signature_from_json(signature_data) if signature_data is not None else None
        ),
        test_id=data.get("test_id"),
        stdout_kind=oracle.get("stdout_kind"),
        stdout_value=oracle.get("stdout_value"),
        stderr_pattern=oracle.get("stderr_pattern"),
    )
    expectation.validate("manifest expectation", allow_unresolved_signature=False)
    return expectation


def _sig_str(signature: CrashSignature) -> str:
    location = signature.function or "?"
    if signature.file:
        location += f" @ {signature.file}"
        if signature.line is not None:
            location += f":{signature.line}"
    return f"{signature.error_type or '?'} in {location}"
