from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, NamedTuple, Protocol

EXIT_BUILD_OR_CONFIG_ERROR = 30
EXIT_VULN_REMAINS = 10
EXIT_FUNC_REGRESSION = 20
EXIT_INCONCLUSIVE = 40
EXIT_PASS = 0


DETECTION_OS_SIGNAL = "OS_SIGNAL"
DETECTION_BINARY_PROTECTION = "BINARY_PROTECTION"
DETECTION_ASAN = "ASAN"
DETECTION_UBSAN = "UBSAN"


ERROR_STACK_BUFFER_OVERFLOW = "stack-buffer-overflow"
ERROR_HEAP_BUFFER_OVERFLOW = "heap-buffer-overflow"
ERROR_HEAP_USE_AFTER_FREE = "heap-use-after-free"
ERROR_NULL_DEREFERENCE = "null-dereference"
ERROR_DIVIDE_BY_ZERO = "divide-by-zero"
ERROR_INTEGER_OVERFLOW = "integer-overflow"
ERROR_STACK_CANARY_ABORT = "stack-canary-abort"
ERROR_UNCLASSIFIED_CRASH = "unclassified-crash"

VERSION_BASE = "base"
VERSION_PATCHED = "patched"
BUILD_TYPE_RELEASE = "release"
BUILD_TYPE_SANITIZED = "sanitized"


STATUS_FIXED = "Fixed"
STATUS_INCOMPLETE_FIX = "Incomplete Fix"
STATUS_NEW_ISSUE = "New Issue"
STATUS_FUNCTIONAL_REGRESSION = "Functional Regression"
STATUS_INCONCLUSIVE = "Inconclusive"


InputMode = Literal["stdin", "file", "args"]
BuildType = Literal["release", "sanitized"]
VersionType = Literal["base", "patched"]


@dataclass
class TargetConfig:
    target_name: str
    repo_path: str
    base_ref: str
    patched_ref: str
    build_cmd_release: str
    build_cmd_sanitized: str
    binary_rel_path: str
    input_mode: InputMode
    timeout_sec: float = 5.0
    memory_mb: int = 512
    cpus: float = 1.0
    env_vars: dict[str, str] = field(default_factory=dict)
    functional_tests_path: str = ""
    security_tests_path: str = ""


@dataclass
class BuildArtifact:
    version: VersionType
    build_type: BuildType
    commit_hash: str
    binary_path: str
    binary_sha256: str
    compile_flags: str
    build_dir: str


@dataclass
class StackFrame:
    index: int
    function: str
    file: str | None = None
    line: int | None = None


@dataclass
class ExecutionResult:
    test_id: str
    version: str
    build_type: str
    exit_code: int
    signal: int | None = None
    timed_out: bool = False
    oom_killed: bool = False
    crashed: bool = False
    error_type: str | None = None
    detection_mechanism: str | None = None
    stack_trace: list[StackFrame] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    stdout_hash: str | None = None
    stderr_excerpt: str | None = None
    duration_ms: int = 0
    cli_command: str = ""


class CrashSignature(NamedTuple):
    error_type: str | None
    function: str | None
    file: str | None
    line: int | None


def crash_signature(result: ExecutionResult) -> CrashSignature:

    top = result.stack_trace[0] if result.stack_trace else None
    return CrashSignature(
        error_type=result.error_type,
        function=top.function if top else None,
        file=top.file if top else None,
        line=top.line if top else None,
    )


def sufficient_crash_evidence(signature: CrashSignature) -> bool:

    return signature.error_type is not None and bool(signature.function)


def strict_crash_match(result: ExecutionResult, target: CrashSignature) -> bool:

    if not result.crashed:
        return False
    if result.timed_out or result.oom_killed:
        return False
    signature = crash_signature(result)
    if not sufficient_crash_evidence(signature) or not sufficient_crash_evidence(
        target
    ):
        return False
    if (
        signature.error_type != target.error_type
        or signature.function != target.function
    ):
        return False
    if (
        signature.line is not None
        and target.line is not None
        and signature.line != target.line
    ):
        return False
    if (
        signature.file is not None
        and target.file is not None
        and signature.file != target.file
    ):
        return False
    return True


class RunnerPort(Protocol):
    def run(
        self,
        input_bytes: bytes,
        *,
        version: str,
        build_type: str,
        timeout_sec: float,
    ) -> ExecutionResult: ...


def assert_execution_context(
    result: ExecutionResult,
    *,
    version: str | None = None,
    build_type: str | None = None,
    test_id: str | None = None,
) -> None:

    for label, actual, expected in (
        ("test_id", result.test_id, test_id),
        ("version", result.version, version),
        ("build_type", result.build_type, build_type),
    ):
        if expected is not None and actual != expected:
            raise ValueError(
                f"execution context mismatch: {label} {actual!r} != "
                f"requested {expected!r}"
            )


@dataclass
class ReplayResult:
    attempt: int
    crashed: bool
    matched: bool = False
    timed_out: bool = False
    oom_killed: bool = False
    error_type: str | None = None
    signature: CrashSignature | None = None


@dataclass
class ReplayReport:
    finding_id: str
    results: list[ReplayResult]
    is_deterministic: bool
    is_flaky: bool
    test_id: str | None = None
    version: str | None = None
    build_type: str | None = None


@dataclass
class HardeningCheck:
    enabled: bool | None
    evidence: str


@dataclass
class HardeningReport:
    binary_path: str
    sha256: str
    nx: HardeningCheck
    pie: HardeningCheck
    relro: str
    relro_evidence: str
    canary: HardeningCheck
    caveats: list[str] = field(default_factory=list)


@dataclass
class HardeningDelta:
    protection: str
    base_value: str
    patched_value: str
    severity: str


@dataclass
class ReproducerArtifact:
    finding_id: str
    bundle_dir: str
    deterministic_replays: str
    is_flaky: bool
    original_size_bytes: int
    minimized_size_bytes: int
    minimized_input_path: str
    regression_test_path: str | None = None
    hardening_report: HardeningReport | None = None
