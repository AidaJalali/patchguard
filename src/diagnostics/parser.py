"""Parse raw execution output into a standardized ExecutionResult."""

from __future__ import annotations

import re
from typing import List, Optional

from src.models import BuildArtifact, ExecutionResult, StackFrame

# ASan: ==ERROR: AddressSanitizer: <type>
_ASAN_ERROR_RE = re.compile(
    r"==ERROR:\s*AddressSanitizer:\s*(.+?)(?:\s+on\s+|\s*$)",
    re.MULTILINE,
)
_ASAN_SEGV_NULL_RE = re.compile(
    r"AddressSanitizer:\s*SEGV\s+on\s+unknown\s+address\s+0x0+",
    re.IGNORECASE,
)
# ASan / UBSan stack frames: #0 0x... in func file:line
_SANITIZER_FRAME_RE = re.compile(
    r"#(?P<idx>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>\S+)"
    r"(?:\s+(?P<path>[^\s:]+):(?P<line>\d+))?",
)

# UBSan: runtime error: <msg>
_UBSAN_RE = re.compile(r"runtime error:\s*(.+)", re.IGNORECASE)

# Stack canary / binary protection
_STACK_SMASH_RE = re.compile(
    r"(\*\*\*\s*stack smashing detected\s*\*\*\*|__stack_chk_fail)",
    re.IGNORECASE,
)

# GDB backtrace frames: #0  func (args) at file:line
_GDB_FRAME_RE = re.compile(
    r"#(?P<idx>\d+)\s+"
    r"(?:0x[0-9a-fA-F]+\s+in\s+)?"
    r"(?P<func>\S+)"
    r"(?:\s+\([^)]*\))?"
    r"(?:\s+at\s+(?P<path>[^\s:]+):(?P<line>\d+))?",
)

_SIGNAL_MAP = {
    139: "SIGSEGV",
    -11: "SIGSEGV",
    134: "SIGABRT",
    -6: "SIGABRT",
    136: "SIGFPE",
    -8: "SIGFPE",
    135: "SIGBUS",
    -7: "SIGBUS",
    132: "SIGILL",
    -4: "SIGILL",
}

_UBSAN_ERROR_MAP = (
    (re.compile(r"division by zero", re.I), "divide-by-zero"),
    (re.compile(r"signed integer overflow", re.I), "integer-overflow"),
    (re.compile(r"load of null pointer|null pointer", re.I), "null-dereference"),
)


class DiagnosticsParser:
    """Normalize sandbox execution metrics into an ExecutionResult."""

    def parse(
        self,
        test_id: str,
        artifact: BuildArtifact,
        exit_code: int,
        stdout: str,
        stderr: str,
        timed_out: bool,
        oom_killed: bool,
        duration_ms: int,
        cli_command: str,
        gdb_backtrace: str = "",
    ) -> ExecutionResult:
        base = {
            "test_id": test_id,
            "version": artifact.version,
            "build_type": artifact.build_type,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": duration_ms,
            "cli_command": cli_command,
        }

        # --- Resource limits (never classified as security crashes) ---
        if timed_out:
            return self._result(
                **base,
                signal=None,
                timed_out=True,
                oom_killed=oom_killed,
                crashed=False,
                error_type="timeout",
                detection_mechanism="TIMEOUT",
                stack_trace=[],
            )

        if oom_killed:
            return self._result(
                **base,
                signal=None,
                timed_out=False,
                oom_killed=True,
                crashed=False,
                error_type="oom",
                detection_mechanism="OOM",
                stack_trace=[],
            )

        combined = f"{stderr}\n{stdout}"

        # --- AddressSanitizer ---
        asan = self._parse_asan(combined)
        if asan is not None:
            error_type, frames = asan
            return self._result(
                **base,
                signal=self._signal_from_exit(exit_code),
                timed_out=False,
                oom_killed=False,
                crashed=True,
                error_type=error_type,
                detection_mechanism="ASAN",
                stack_trace=frames,
            )

        # --- UndefinedBehaviorSanitizer ---
        ubsan = self._parse_ubsan(combined)
        if ubsan is not None:
            error_type, frames = ubsan
            return self._result(
                **base,
                signal=self._signal_from_exit(exit_code),
                timed_out=False,
                oom_killed=False,
                crashed=True,
                error_type=error_type,
                detection_mechanism="UBSAN",
                stack_trace=frames,
            )

        # --- Binary protection (stack canary) ---
        if _STACK_SMASH_RE.search(combined):
            return self._result(
                **base,
                signal=self._signal_from_exit(exit_code) or "SIGABRT",
                timed_out=False,
                oom_killed=False,
                crashed=True,
                error_type="stack-canary-abort",
                detection_mechanism="BINARY_PROTECTION",
                stack_trace=self._parse_sanitizer_frames(combined),
            )

        # --- OS signals ---
        signal = self._signal_from_exit(exit_code)
        if signal is not None:
            frames: List[StackFrame] = []
            if gdb_backtrace:
                frames = self._parse_gdb_frames(gdb_backtrace)
            elif artifact.build_type == "release":
                frames = self._parse_gdb_frames(combined)

            return self._result(
                **base,
                signal=signal,
                timed_out=False,
                oom_killed=False,
                crashed=True,
                error_type="unclassified-crash",
                detection_mechanism="OS_SIGNAL",
                stack_trace=frames,
            )

        # --- Clean run ---
        return self._result(
            **base,
            signal=None,
            timed_out=False,
            oom_killed=False,
            crashed=False,
            error_type="none",
            detection_mechanism="NONE",
            stack_trace=[],
        )

    # ------------------------------------------------------------------ #
    # Parsers
    # ------------------------------------------------------------------ #

    def _parse_asan(self, text: str) -> Optional[tuple]:
        if _ASAN_SEGV_NULL_RE.search(text):
            return "null-dereference", self._parse_sanitizer_frames(text)

        match = _ASAN_ERROR_RE.search(text)
        if not match:
            return None

        raw_type = match.group(1).strip()
        # Normalize "SEGV on unknown address ..." already handled above;
        # strip trailing address phrasing if present.
        raw_type = re.split(r"\s+on\s+", raw_type, maxsplit=1)[0].strip()
        known = {
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "heap-use-after-free",
            "stack-use-after-return",
            "global-buffer-overflow",
            "use-after-poison",
            "double-free",
        }
        error_type = raw_type if raw_type in known else raw_type.lower().replace(" ", "-")
        if "null" in error_type or error_type.startswith("segv"):
            error_type = "null-dereference"
        return error_type, self._parse_sanitizer_frames(text)

    def _parse_ubsan(self, text: str) -> Optional[tuple]:
        match = _UBSAN_RE.search(text)
        if not match:
            return None
        msg = match.group(1).strip()
        error_type = "unclassified-crash"
        for pattern, mapped in _UBSAN_ERROR_MAP:
            if pattern.search(msg):
                error_type = mapped
                break
        return error_type, self._parse_sanitizer_frames(text)

    def _parse_sanitizer_frames(self, text: str) -> List[StackFrame]:
        frames: List[StackFrame] = []
        for match in _SANITIZER_FRAME_RE.finditer(text):
            line_number = None
            if match.group("line"):
                line_number = int(match.group("line"))
            frames.append(
                StackFrame(
                    frame_index=int(match.group("idx")),
                    function_name=match.group("func"),
                    file_path=match.group("path"),
                    line_number=line_number,
                )
            )
        return frames

    def _parse_gdb_frames(self, text: str) -> List[StackFrame]:
        frames: List[StackFrame] = []
        for match in _GDB_FRAME_RE.finditer(text):
            func = match.group("func")
            # Skip gdb noise frames
            if func in ("??",):
                continue
            line_number = None
            if match.group("line"):
                line_number = int(match.group("line"))
            frames.append(
                StackFrame(
                    frame_index=int(match.group("idx")),
                    function_name=func,
                    file_path=match.group("path"),
                    line_number=line_number,
                )
            )
        return frames

    @staticmethod
    def _signal_from_exit(exit_code: int) -> Optional[str]:
        if exit_code in _SIGNAL_MAP:
            return _SIGNAL_MAP[exit_code]
        # Generic: exit_code = 128 + signal_number
        if exit_code >= 128:
            sig_num = exit_code - 128
            generic = {
                11: "SIGSEGV",
                6: "SIGABRT",
                8: "SIGFPE",
                7: "SIGBUS",
                4: "SIGILL",
                9: "SIGKILL",
            }
            return generic.get(sig_num)
        if exit_code < 0:
            return _SIGNAL_MAP.get(exit_code)
        return None

    @staticmethod
    def _result(**kwargs) -> ExecutionResult:
        return ExecutionResult(**kwargs)
