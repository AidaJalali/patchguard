import json
import re
from dataclasses import dataclass
from pathlib import Path

from models import ExecutionResult


class OracleError(ValueError):
    pass


@dataclass(frozen=True)
class OracleExpectation:
    test_id: str
    expected_exit_code: int
    is_valid_input: bool
    stdout_kind: str
    stdout_value: object
    expected_stderr_pattern: str | None = None


@dataclass
class OracleResult:
    test_id: str
    version: str
    build_type: str
    passed: bool
    is_valid_input: bool
    reasons: list[str]


@dataclass
class OracleSuite:
    reference_source: str
    expectations: dict[str, OracleExpectation]


def _json(text):
    def reject_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")

    return json.loads(text, parse_constant=reject_constant)


def load_oracle(path: str | Path) -> OracleSuite:

    try:
        data = _json(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise OracleError(f"cannot load oracle: {exc}") from exc
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("reference_source"), str)
        or not data["reference_source"].strip()
    ):
        raise OracleError("oracle requires a nonempty independent reference_source")
    tests = data.get("tests")
    if not isinstance(tests, list) or not tests:
        raise OracleError("oracle requires a nonempty tests list")
    expectations = {}
    for row in tests:
        if not isinstance(row, dict):
            raise OracleError("oracle tests must be objects")
        tid = row.get("test_id")
        if not isinstance(tid, str) or not tid or tid in expectations:
            raise OracleError("test IDs must be nonempty and unique")
        if (
            type(row.get("expected_exit_code")) is not int
            or type(row.get("is_valid_input")) is not bool
        ):
            raise OracleError(
                f"{tid}: explicit integer exit code and boolean is_valid_input required"
            )
        matchers = [
            k
            for k in (
                "expected_stdout_exact",
                "expected_stdout_regex",
                "expected_stdout_json",
            )
            if k in row
        ]
        if len(matchers) != 1:
            raise OracleError(f"{tid}: exactly one stdout matcher required")
        key = matchers[0]
        for pattern in (
            row.get("expected_stderr_pattern"),
            row[key] if key.endswith("regex") else None,
        ):
            if pattern is not None:
                if not isinstance(pattern, str):
                    raise OracleError(f"{tid}: regex must be a string")
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise OracleError(f"{tid}: invalid regex: {exc}") from exc
        if not key.endswith("json") and not isinstance(row[key], str):
            raise OracleError(f"{tid}: stdout matcher must be a string")
        expectations[tid] = OracleExpectation(
            tid,
            row["expected_exit_code"],
            row["is_valid_input"],
            key.rsplit("_", 1)[1],
            row[key],
            row.get("expected_stderr_pattern"),
        )
    return OracleSuite(data["reference_source"], expectations)


def _json_equal(a, b):

    if type(a) is not type(b):
        return type(a) in (int, float) and type(b) in (int, float) and a == b
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
    return a == b


def evaluate(result: ExecutionResult, expectation: OracleExpectation) -> OracleResult:
    if result.test_id != expectation.test_id:
        raise OracleError("execution test_id does not match oracle")
    reasons = []
    if (
        result.crashed
        or result.signal is not None
        or result.timed_out
        or result.oom_killed
    ):
        reasons.append("execution crashed or was terminated by signal/resource limits")
    if result.exit_code != expectation.expected_exit_code:
        reasons.append(
            f"exit code {result.exit_code} != {expectation.expected_exit_code}"
        )
    kind, value = expectation.stdout_kind, expectation.stdout_value
    if kind == "exact":
        matched = result.stdout == value
    elif kind == "regex":
        matched = re.fullmatch(value, result.stdout) is not None
    elif kind == "json":
        try:
            matched = _json_equal(_json(result.stdout), value)
        except ValueError:
            matched = False
    else:
        raise OracleError(f"unknown stdout matcher: {kind}")
    if not matched:
        reasons.append(f"stdout does not satisfy independent {kind} expectation")
    if (
        expectation.expected_stderr_pattern is not None
        and re.search(expectation.expected_stderr_pattern, result.stderr) is None
    ):
        reasons.append("stderr does not match reference pattern")
    return OracleResult(
        result.test_id,
        result.version,
        result.build_type,
        not reasons,
        expectation.is_valid_input,
        reasons,
    )


def evaluate_suite(
    results: list[ExecutionResult], suite: OracleSuite
) -> list[OracleResult]:

    keys = [(r.test_id, r.version, r.build_type) for r in results]
    if len(set(keys)) != len(keys):
        raise OracleError("duplicate execution results")
    for version in ("base", "patched"):
        for build in ("release", "sanitized"):
            if any((tid, version, build) not in keys for tid in suite.expectations):
                raise OracleError(f"missing oracle executions for {version}/{build}")
    try:
        return [evaluate(r, suite.expectations[r.test_id]) for r in results]
    except KeyError as exc:
        raise OracleError(f"no reference expectation for {exc.args[0]}") from exc
