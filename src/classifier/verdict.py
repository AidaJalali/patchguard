from dataclasses import asdict, dataclass, field, replace

from correlator.correlator import DiffCorrelation
from models import (
    STATUS_FIXED,
    STATUS_FUNCTIONAL_REGRESSION,
    STATUS_INCOMPLETE_FIX,
    STATUS_INCONCLUSIVE,
    STATUS_NEW_ISSUE,
    ExecutionResult,
    ReplayReport,
    ReproducerArtifact,
    StackFrame,
    crash_signature,
    strict_crash_match,
    sufficient_crash_evidence,
)
from oracle.functional_oracle import OracleResult


@dataclass
class Finding:
    finding_id: str
    status: str
    correlation_confidence: str
    matched_diff_files: list[str]
    matched_functions: list[str]
    evidence_explanation: str
    test_id: str
    build_type: str
    base_execution: dict
    patched_execution: dict
    oracle_results: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _confirmed(
    result: ExecutionResult,
    replay: ReplayReport | None,
    artifact: ReproducerArtifact | None,
) -> bool:
    signature = crash_signature(result)
    if (
        not result.crashed
        or result.timed_out
        or result.oom_killed
        or not sufficient_crash_evidence(signature)
        or not (
            result.signal is not None
            or result.detection_mechanism
            in ("ASAN", "UBSAN", "BINARY_PROTECTION", "OS_SIGNAL")
        )
    ):
        return False
    if artifact is not None and artifact.is_flaky:
        return False
    if (
        not replay
        or not replay.is_deterministic
        or replay.is_flaky
        or not replay.results
    ):
        return False

    if not replay.test_id or not replay.version or not replay.build_type:
        return False
    attempts = [r.attempt for r in replay.results]
    if any(type(i) is not int for i in attempts) or set(attempts) != set(
        range(1, len(attempts) + 1)
    ):
        return False
    for record in replay.results:
        if not record.signature or not record.matched:
            return False
        signature = record.signature
        replay_execution = replace(
            result,
            crashed=record.crashed,
            timed_out=record.timed_out,
            oom_killed=record.oom_killed,
            error_type=signature.error_type,
            stack_trace=[
                StackFrame(0, signature.function, signature.file, signature.line)
            ]
            if signature.function
            else [],
        )
        if not strict_crash_match(replay_execution, crash_signature(result)):
            return False
    return True


def classify_pair(
    finding_id: str,
    base: ExecutionResult,
    patched: ExecutionResult,
    *,
    correlation: DiffCorrelation,
    base_oracle: OracleResult | None = None,
    patched_oracle: OracleResult | None = None,
    base_replay: ReplayReport | None = None,
    patched_replay: ReplayReport | None = None,
    base_artifact: ReproducerArtifact | None = None,
    patched_artifact: ReproducerArtifact | None = None,
) -> Finding:

    if base.version != "base" or patched.version != "patched":
        raise ValueError("expected base and patched executions in that order")
    if base.test_id != patched.test_id or base.build_type != patched.build_type:
        raise ValueError(
            "compare the same test and build type; never mix release/sanitized"
        )
    if base.build_type not in ("release", "sanitized"):
        raise ValueError("unknown build type")
    if correlation.finding_id != finding_id:
        raise ValueError("correlation belongs to a different finding")
    for result, oracle in ((base, base_oracle), (patched, patched_oracle)):
        if oracle and (oracle.test_id, oracle.version, oracle.build_type) != (
            result.test_id,
            result.version,
            result.build_type,
        ):
            raise ValueError("oracle belongs to a different execution")
    if (
        base_oracle
        and patched_oracle
        and base_oracle.is_valid_input != patched_oracle.is_valid_input
    ):
        raise ValueError("oracle validity must agree across versions")
    for replay, artifact in (
        (base_replay, base_artifact),
        (patched_replay, patched_artifact),
    ):
        if (replay and replay.finding_id != finding_id) or (
            artifact and artifact.finding_id != finding_id
        ):
            raise ValueError("replay/artifact belongs to a different finding")
    for replay, result in ((base_replay, base), (patched_replay, patched)):
        if replay is None:
            continue
        for label, claim, actual in (
            ("test_id", replay.test_id, result.test_id),
            ("version", replay.version, result.version),
            ("build_type", replay.build_type, result.build_type),
        ):
            if claim is not None and claim != actual:
                raise ValueError(
                    f"replay {label} {claim!r} does not match the execution "
                    f"being classified ({label}={actual!r}); replay evidence "
                    "from another context must never confirm a finding"
                )

    def finding(status, explanation):
        return Finding(
            finding_id,
            status,
            correlation.correlation_confidence,
            correlation.matched_diff_files,
            correlation.matched_functions,
            explanation + " " + correlation.evidence_explanation,
            base.test_id,
            base.build_type,
            asdict(base),
            asdict(patched),
            {
                v: asdict(o)
                for v, o in (("base", base_oracle), ("patched", patched_oracle))
                if o
            },
        )

    if any(r.timed_out or r.oom_killed for r in (base, patched)):
        return finding(
            STATUS_INCONCLUSIVE,
            "Resource-limit termination is not proof of a fix or vulnerability.",
        )
    if any(a and a.is_flaky for a in (base_artifact, patched_artifact)):
        return finding(
            STATUS_INCONCLUSIVE, "Reproducer pipeline marked the finding inconclusive."
        )

    if (
        not base.crashed
        and not patched.crashed
        and base_oracle
        and patched_oracle
        and base_oracle.is_valid_input
        and base_oracle.passed
        and not patched_oracle.passed
    ):
        return finding(
            STATUS_FUNCTIONAL_REGRESSION,
            "Valid input passed the independent oracle on base and failed it on patched.",
        )
    if not correlation.proven:
        return finding(STATUS_INCONCLUSIVE, "Patch correlation is not established.")
    if base.crashed:
        if not _confirmed(base, base_replay, base_artifact):
            return finding(
                STATUS_INCONCLUSIVE,
                "Base crash lacks confirmed replay/diagnostic evidence.",
            )
        if patched.crashed:
            if _confirmed(
                patched, patched_replay, patched_artifact
            ) and strict_crash_match(patched, crash_signature(base)):
                return finding(
                    STATUS_INCOMPLETE_FIX,
                    "The same confirmed vulnerability still reproduces on patched input.",
                )
            return finding(
                STATUS_INCONCLUSIVE,
                "Patched crash is unconfirmed or its relationship to the base crash is unresolved.",
            )
        if patched.signal is None and patched_oracle and patched_oracle.passed:
            return finding(
                STATUS_FIXED,
                "Base crash reproduced; patched satisfies the independent oracle without crashing.",
            )
        return finding(
            STATUS_INCONCLUSIVE,
            "Absence of a patched crash alone does not prove correct behavior.",
        )
    if patched.crashed:
        if base.signal is None and _confirmed(
            patched, patched_replay, patched_artifact
        ):
            return finding(
                STATUS_NEW_ISSUE,
                "Input did not crash base, but a confirmed, patch-related crash occurs on patched.",
            )
        return finding(
            STATUS_INCONCLUSIVE,
            "Patched crash lacks confirmed evidence or base did not terminate normally.",
        )
    return finding(
        STATUS_INCONCLUSIVE,
        "This execution pair does not establish a reproduced security finding or functional regression.",
    )
