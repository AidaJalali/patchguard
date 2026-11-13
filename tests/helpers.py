from __future__ import annotations

from models import ExecutionResult, StackFrame


class MockRunner:
    def __init__(
        self, script: dict[bytes, ExecutionResult] | None = None, default=None
    ):
        self._script = script or {}
        self._default = default
        self.calls: list[bytes] = []

    def run(
        self,
        input_bytes: bytes,
        *,
        version: str = "base",
        build_type: str = "sanitized",
        timeout_sec: float = 5.0,
    ) -> ExecutionResult:
        self.calls.append(input_bytes)
        result = self._script.get(input_bytes)
        if result is None and self._default is not None:
            result = self._default(input_bytes)
        if result is None:
            raise AssertionError(f"MockRunner: unscripted input {input_bytes!r}")
        return result

    @property
    def call_count(self) -> int:
        return len(self.calls)


def make_crash(
    error_type: str = "heap-buffer-overflow",
    function: str = "copy_data",
    file: str = "src/parse.c",
    line: int = 42,
    **overrides,
) -> ExecutionResult:
    kwargs = dict(
        test_id="t1",
        version="base",
        build_type="sanitized",
        exit_code=1,
        signal=6,
        crashed=True,
        error_type=error_type,
        detection_mechanism="ASAN",
        stack_trace=[StackFrame(index=0, function=function, file=file, line=line)],
        stderr="ERROR: AddressSanitizer: heap-buffer-overflow",
    )
    kwargs.update(overrides)
    return ExecutionResult(**kwargs)


def make_clean(**overrides) -> ExecutionResult:
    kwargs = dict(
        test_id="t1",
        version="base",
        build_type="sanitized",
        exit_code=0,
        crashed=False,
        stdout="ok",
    )
    kwargs.update(overrides)
    return ExecutionResult(**kwargs)
