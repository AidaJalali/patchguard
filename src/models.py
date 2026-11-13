"""Shared data contracts for the patch_validator pipeline."""

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

InputMode = Literal["stdin", "file", "args"]
BuildType = Literal["release", "sanitized"]
VersionType = Literal["base", "patched"]
DetectionMechanism = Literal[
    "NONE",
    "OS_SIGNAL",
    "BINARY_PROTECTION",
    "ASAN",
    "UBSAN",
    "TIMEOUT",
    "OOM",
]


@dataclass
class TargetConfig:
    target_name: str
    repo_path: str
    base_ref: str
    patched_ref: str
    build_cmd_release: str
    build_cmd_sanitized: str
    binary_rel_path: str
    input_mode: InputMode  # "stdin" | "file" | "args"
    timeout_sec: float = 5.0
    memory_mb: int = 512
    cpus: float = 1.0
    env_vars: Dict[str, str] = field(default_factory=dict)
    functional_tests_path: str = ""
    security_tests_path: str = ""


@dataclass
class BuildArtifact:
    version: VersionType  # "base" | "patched"
    build_type: BuildType  # "release" | "sanitized"
    commit_hash: str
    binary_path: str
    binary_sha256: str
    compile_flags: str
    build_dir: str


@dataclass
class StackFrame:
    frame_index: int
    function_name: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class ExecutionResult:
    test_id: str
    version: VersionType
    build_type: BuildType
    exit_code: int
    signal: Optional[str]  # e.g., "SIGSEGV", "SIGABRT", "SIGFPE", None
    timed_out: bool
    oom_killed: bool
    crashed: bool
    error_type: str  # e.g., "heap-buffer-overflow", "none", ...
    detection_mechanism: DetectionMechanism
    stack_trace: List[StackFrame] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    cli_command: str = ""
