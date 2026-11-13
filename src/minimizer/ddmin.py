from __future__ import annotations

from collections.abc import Callable

from models import (
    ExecutionResult,
    RunnerPort,
    assert_execution_context,
    crash_signature,
    strict_crash_match,
)


class MinimizationError(ValueError):
    pass


def ddmin(
    initial: bytes,
    test: Callable[[bytes], bool],
    *,
    max_iterations: int | None = None,
) -> bytes:

    if not test(initial):
        raise MinimizationError("ddmin: initial input does not satisfy the predicate")

    current = initial
    n = 2
    iterations = 0

    while len(current) >= 2:
        iterations += 1
        if max_iterations is not None and iterations > max_iterations:
            return current

        chunk_size = len(current) // n
        reduced = False
        for i in range(n):
            start = i * chunk_size
            end = min((i + 1) * chunk_size, len(current))
            candidate = current[:start] + current[end:]
            if test(candidate):
                current = candidate
                n = max(n - 1, 2)
                reduced = True
                break

        if not reduced:
            if n >= len(current):
                break
            n = min(n * 2, len(current))

    if current and test(b""):
        current = b""
    return current


class CrashSignaturePredicate:
    def __init__(
        self,
        runner: RunnerPort,
        original: ExecutionResult,
        *,
        version: str | None = None,
        build_type: str | None = None,
        test_id: str | None = None,
        timeout_sec: float = 5.0,
        strict: bool = True,
    ) -> None:
        self._runner = runner
        self.signature = crash_signature(original)
        self._version = version if version is not None else original.version
        self._build_type = build_type if build_type is not None else original.build_type
        self._test_id = test_id if test_id is not None else original.test_id
        for label, selected, baseline in (
            ("version", self._version, original.version),
            ("build_type", self._build_type, original.build_type),
            ("test_id", self._test_id, original.test_id),
        ):
            if selected != baseline:
                raise ValueError(
                    f"cannot reuse the crash signature from "
                    f"{label}={baseline!r} under execution context "
                    f"{label}={selected!r}; obtain a real ExecutionResult "
                    "from that context and construct a new predicate from it"
                )
        self._timeout_sec = timeout_sec
        self.strict = strict
        self.runs = 0

    def __call__(self, candidate: bytes) -> bool:
        self.runs += 1
        result = self._runner.run(
            candidate,
            version=self._version,
            build_type=self._build_type,
            timeout_sec=self._timeout_sec,
        )
        assert_execution_context(
            result,
            version=self._version,
            build_type=self._build_type,
            test_id=self._test_id,
        )
        if not result.crashed or result.timed_out or result.oom_killed:
            return False
        if self.strict:
            return strict_crash_match(result, self.signature)

        return (
            result.error_type is not None
            and result.error_type == self.signature.error_type
        )
