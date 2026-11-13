from __future__ import annotations

import hashlib
import json
import re
import shlex
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from minimizer.ddmin import CrashSignaturePredicate, MinimizationError, ddmin
from models import (
    ExecutionResult,
    ReplayReport,
    ReplayResult,
    ReproducerArtifact,
    RunnerPort,
    assert_execution_context,
    crash_signature,
    strict_crash_match,
    sufficient_crash_evidence,
)

DEFAULT_TIMEOUT_SEC = 5.0
INPUT_PLACEHOLDER = "{input}"
INPUT_MODES = ("stdin", "file", "args")
_FINDING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class BundleError(Exception):
    pass


@dataclass
class FindingContext:
    finding_id: str
    input_bytes: bytes
    original: ExecutionResult
    binary_path: Path
    input_mode: str
    argv_template: list[str] = field(default_factory=list)

    cli_command: str = ""
    base_commit_hash: str | None = None
    patched_commit_hash: str | None = None
    compile_flags: str | None = None
    env_vars: dict[str, str] = field(default_factory=dict)


@dataclass
class MinimizationResult:
    input_bytes: bytes
    skipped: bool = False
    skip_reason: str | None = None
    candidate_runs: int = 0
    revalidated: bool | None = None


def verify_reproducibility(
    runner: RunnerPort,
    input_bytes: bytes,
    original: ExecutionResult,
    *,
    finding_id: str,
    n: int = 3,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
) -> ReplayReport:

    if n < 1:
        raise ValueError(f"n must be >= 1, got {n}")
    target = crash_signature(original)
    results: list[ReplayResult] = []
    for attempt in range(1, n + 1):
        result = runner.run(
            input_bytes,
            version=original.version,
            build_type=original.build_type,
            timeout_sec=timeout_sec,
        )
        assert_execution_context(
            result,
            version=original.version,
            build_type=original.build_type,
            test_id=original.test_id,
        )
        matched = strict_crash_match(result, target)
        results.append(
            ReplayResult(
                attempt=attempt,
                crashed=result.crashed,
                matched=matched,
                timed_out=result.timed_out,
                oom_killed=result.oom_killed,
                error_type=result.error_type,
                signature=crash_signature(result),
            )
        )
    is_deterministic = all(r.matched for r in results)
    return ReplayReport(
        finding_id=finding_id,
        results=results,
        is_deterministic=is_deterministic,
        is_flaky=not is_deterministic,
        test_id=original.test_id,
        version=original.version,
        build_type=original.build_type,
    )


def minimize_input(
    runner: RunnerPort,
    input_bytes: bytes,
    original: ExecutionResult,
    *,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    max_iterations: int | None = None,
) -> MinimizationResult:

    predicate = CrashSignaturePredicate(
        runner, original, timeout_sec=timeout_sec, strict=True
    )
    try:
        minimized = ddmin(input_bytes, predicate, max_iterations=max_iterations)
    except MinimizationError:
        return MinimizationResult(
            input_bytes=input_bytes,
            skipped=True,
            skip_reason="nondeterministic_precheck_failed",
            candidate_runs=predicate.runs,
            revalidated=False,
        )
    if not predicate(minimized):
        return MinimizationResult(
            input_bytes=input_bytes,
            skipped=True,
            skip_reason="revalidation_failed",
            candidate_runs=predicate.runs,
            revalidated=False,
        )
    return MinimizationResult(
        input_bytes=minimized,
        candidate_runs=predicate.runs,
        revalidated=True,
    )


def build_reproducer(
    finding: FindingContext,
    runner: RunnerPort,
    *,
    n: int = 3,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    max_iterations: int | None = None,
    output_root: str | Path = "reproducers",
) -> ReproducerArtifact:

    replay = verify_reproducibility(
        runner,
        finding.input_bytes,
        finding.original,
        finding_id=finding.finding_id,
        n=n,
        timeout_sec=timeout_sec,
    )
    if not sufficient_crash_evidence(crash_signature(finding.original)):
        minimized = MinimizationResult(
            input_bytes=finding.input_bytes,
            skipped=True,
            skip_reason="insufficient_crash_evidence",
        )
    elif replay.is_flaky:
        minimized = MinimizationResult(
            input_bytes=finding.input_bytes, skipped=True, skip_reason="flaky"
        )
    else:
        minimized = minimize_input(
            runner,
            finding.input_bytes,
            finding.original,
            timeout_sec=timeout_sec,
            max_iterations=max_iterations,
        )
    return create_bundle(
        finding, replay=replay, minimized=minimized, output_root=output_root
    )


def create_bundle(
    finding: FindingContext,
    *,
    replay: ReplayReport,
    minimized: MinimizationResult,
    output_root: str | Path = "reproducers",
) -> ReproducerArtifact:

    _validate_context(finding)

    bundle_dir = Path(output_root) / finding.finding_id
    _ensure_inside(bundle_dir, output_root)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    if not finding.binary_path.is_file():
        raise BundleError(f"binary not found: {finding.binary_path}")
    copied_binary = bundle_dir / "binary"
    shutil.copy2(finding.binary_path, copied_binary)
    copied_binary.chmod(copied_binary.stat().st_mode | 0o111)

    (bundle_dir / "crashing_input.bin").write_bytes(finding.input_bytes)
    (bundle_dir / "minimized_input.bin").write_bytes(minimized.input_bytes)

    metadata = _metadata(finding, replay, minimized, copied_binary)
    (bundle_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )

    (bundle_dir / "reproduce.sh").write_text(_generate_reproduce_script(finding))
    (bundle_dir / "reproduce.sh").chmod(0o755)

    matching = sum(1 for r in replay.results if r.matched)

    effective_flaky = replay.is_flaky or minimized.skipped
    return ReproducerArtifact(
        finding_id=finding.finding_id,
        bundle_dir=str(bundle_dir),
        deterministic_replays=f"{matching}/{len(replay.results)}",
        is_flaky=effective_flaky,
        original_size_bytes=len(finding.input_bytes),
        minimized_size_bytes=len(minimized.input_bytes),
        minimized_input_path=str(bundle_dir / "minimized_input.bin"),
    )


def _validate_context(finding: FindingContext) -> None:
    _validate_finding_id(finding.finding_id)
    if finding.input_mode not in INPUT_MODES:
        raise BundleError(
            f"input_mode must be one of {INPUT_MODES}, got {finding.input_mode!r}"
        )
    placeholders = sum(1 for p in finding.argv_template if p == INPUT_PLACEHOLDER)
    if finding.input_mode == "stdin":
        if placeholders != 0:
            raise BundleError(
                "stdin mode: argv_template must not contain the {input} placeholder"
            )
    elif placeholders != 1:
        raise BundleError(
            f"{finding.input_mode} mode: argv_template must contain exactly one "
            f"{INPUT_PLACEHOLDER} placeholder, found {placeholders}"
        )
    for name, value in finding.env_vars.items():
        if not _ENV_NAME_RE.fullmatch(name):
            raise BundleError(
                f"invalid env var name {name!r}: must match [A-Za-z_][A-Za-z0-9_]*"
            )
        if "\x00" in name or "\x00" in value:
            raise BundleError("env var names and values must not contain null bytes")


def _validate_finding_id(finding_id: str) -> None:
    if not _FINDING_ID_RE.fullmatch(finding_id):
        raise BundleError(
            f"invalid finding_id {finding_id!r}: use only letters, digits, '.', '_', '-' "
            "(no path separators)"
        )


def _ensure_inside(bundle_dir: Path, output_root: str | Path) -> None:
    root = Path(output_root).resolve()
    if not bundle_dir.resolve().is_relative_to(root):
        raise BundleError(f"bundle dir {bundle_dir} escapes output root {output_root}")


def _metadata(
    finding: FindingContext,
    replay: ReplayReport,
    minimized: MinimizationResult,
    copied_binary: Path,
) -> dict:
    crash = finding.original
    top = crash.stack_trace[0] if crash.stack_trace else None
    return {
        "finding_id": finding.finding_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "commit": {
            "base": finding.base_commit_hash,
            "patched": finding.patched_commit_hash,
        },
        "binary": {
            "source_path": str(finding.binary_path),
            "sha256": _sha256(copied_binary),
            "dependencies": _binary_dependencies(copied_binary),
        },
        "build": {
            "build_type": crash.build_type,
            "compile_flags": finding.compile_flags,
            "env_vars": finding.env_vars,
        },
        "invocation": {
            "input_mode": finding.input_mode,
            "argv_template": finding.argv_template,
            "cli_command": finding.cli_command,
        },
        "crash": {
            "version": crash.version,
            "error_type": crash.error_type,
            "detection_mechanism": crash.detection_mechanism,
            "exit_code": crash.exit_code,
            "signal": crash.signal,
            "top_frame": (
                {"function": top.function, "file": top.file, "line": top.line}
                if top
                else None
            ),
            "stack_trace": [asdict(frame) for frame in crash.stack_trace],
        },
        "replay": {
            "test_id": replay.test_id,
            "version": replay.version,
            "build_type": replay.build_type,
            "total": len(replay.results),
            "matching": sum(1 for r in replay.results if r.matched),
            "deterministic": replay.is_deterministic,
            "is_flaky": replay.is_flaky,
            "results": [asdict(r) for r in replay.results],
        },
        "minimization": {
            "skipped": minimized.skipped,
            "skip_reason": minimized.skip_reason,
            "algorithm": None if minimized.skipped else "ddmin",
            "candidate_runs": minimized.candidate_runs,
            "revalidated": minimized.revalidated,
            "original_size_bytes": len(finding.input_bytes),
            "minimized_size_bytes": len(minimized.input_bytes),
        },
    }


def _generate_reproduce_script(finding: FindingContext) -> str:

    lines = [
        "#!/bin/sh",
        "set -u",
        'SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"',
        'BINARY="$SCRIPT_DIR/binary"',
        'INPUT="$SCRIPT_DIR/crashing_input.bin"',
        'NAME="crashing_input.bin"',
        'case "${1:-}" in',
        '  minimized) INPUT="$SCRIPT_DIR/minimized_input.bin"; NAME="minimized_input.bin" ;;',
        '  "") : ;;',
        '  *) echo "usage: $0 [minimized]" >&2; exit 2 ;;',
        "esac",
    ]

    env_prefix = ""
    if finding.env_vars:
        pairs = [
            shlex.quote(f"{key}={value}") for key, value in finding.env_vars.items()
        ]
        env_prefix = "env " + " ".join(pairs) + " "
        lines.append("# target env vars applied only to the child process (env)")

    parts = ['"$BINARY"']
    for arg in finding.argv_template:
        if arg == INPUT_PLACEHOLDER:
            if finding.input_mode == "file":
                parts.append('"$INPUT"')
            elif finding.input_mode == "args":
                parts.append('$(cat "$INPUT")')
        else:
            parts.append(shlex.quote(arg))
    if finding.input_mode == "stdin":
        run_line = env_prefix + " ".join(parts) + ' < "$INPUT"'
    else:
        run_line = env_prefix + " ".join(parts)

    run_lines = []
    if finding.input_mode == "args":
        run_lines.append("set -f")
    run_lines.append(run_line)
    run_lines.append("status=$?")
    if finding.input_mode == "args":
        run_lines.append("set +f")

    lines += [
        "",
        'echo "replaying: $NAME" >&2',
        *run_lines,
        'echo "binary exited with status $status" >&2',
        'exit "$status"',
    ]
    return "\n".join(lines) + "\n"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _binary_dependencies(binary_path: Path) -> list[str]:

    proc = subprocess.run(
        ["readelf", "-d", "-W", str(binary_path)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return []
    return re.findall(r"\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]", proc.stdout)
