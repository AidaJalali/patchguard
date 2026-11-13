from helpers import make_crash

from models import (
    EXIT_BUILD_OR_CONFIG_ERROR,
    EXIT_FUNC_REGRESSION,
    EXIT_INCONCLUSIVE,
    EXIT_PASS,
    EXIT_VULN_REMAINS,
    ExecutionResult,
    ReproducerArtifact,
    StackFrame,
    crash_signature,
    strict_crash_match,
    sufficient_crash_evidence,
)


def test_exit_code_priority_values():

    assert EXIT_BUILD_OR_CONFIG_ERROR == 30
    assert EXIT_VULN_REMAINS == 10
    assert EXIT_FUNC_REGRESSION == 20
    assert EXIT_INCONCLUSIVE == 40
    assert EXIT_PASS == 0


def test_execution_result_contract_fields():

    result = ExecutionResult(
        test_id="t", version="base", build_type="release", exit_code=0
    )
    assert result.signal is None
    assert result.timed_out is False
    assert result.oom_killed is False
    assert result.crashed is False
    assert result.error_type is None
    assert result.detection_mechanism is None
    assert result.stack_trace == []
    assert result.stdout == ""
    assert result.stderr == ""


def test_reproducer_artifact_contract_fields():

    artifact = ReproducerArtifact(
        finding_id="f1",
        bundle_dir="reproducers/f1",
        deterministic_replays="3/3",
        is_flaky=False,
        original_size_bytes=4096,
        minimized_size_bytes=16,
        minimized_input_path="reproducers/f1/minimized_input.bin",
    )
    assert artifact.regression_test_path is None
    assert artifact.hardening_report is None


def test_crash_signature_uses_top_frame():
    result = make_crash(
        error_type="heap-buffer-overflow",
        function="copy_data",
        file="src/parse.c",
        line=42,
    )
    signature = crash_signature(result)
    assert signature == ("heap-buffer-overflow", "copy_data", "src/parse.c", 42)


def test_crash_signature_without_stack_trace():
    result = make_crash(stack_trace=[], function="unused")
    signature = crash_signature(result)
    assert signature.error_type == "heap-buffer-overflow"
    assert signature.function is None and signature.line is None


def test_crash_signature_takes_only_first_frame():
    result = make_crash()
    result.stack_trace.append(
        StackFrame(index=1, function="caller", file="a.c", line=1)
    )
    assert crash_signature(result).function == "copy_data"


class TestCrashEquivalence:
    def test_missing_error_type_is_insufficient_evidence(self):
        assert not sufficient_crash_evidence(
            crash_signature(make_crash(error_type=None))
        )

    def test_missing_frames_is_insufficient_evidence(self):
        assert not sufficient_crash_evidence(
            crash_signature(make_crash(stack_trace=[]))
        )

    def test_frame_without_line_info_is_sufficient_evidence(self):
        assert sufficient_crash_evidence(crash_signature(make_crash(line=None)))

    def test_two_results_without_evidence_never_match(self):
        a = make_crash(error_type=None, stack_trace=[])
        b = make_crash(error_type=None, stack_trace=[])
        assert not strict_crash_match(b, crash_signature(a))

    def test_line_compared_only_when_both_sides_have_it(self):
        target = crash_signature(make_crash(line=None))
        assert strict_crash_match(make_crash(line=7), target)

    def test_different_line_rejected_when_both_present(self):
        target = crash_signature(make_crash(line=42))
        assert not strict_crash_match(make_crash(line=43), target)

    def test_different_function_rejected(self):
        target = crash_signature(make_crash(function="copy_data"))
        assert not strict_crash_match(make_crash(function="other_fn"), target)

    def test_different_error_type_rejected(self):
        target = crash_signature(make_crash())
        assert not strict_crash_match(make_crash(error_type="null-dereference"), target)

    def test_timeout_and_oom_never_match(self):
        target = crash_signature(make_crash())
        assert not strict_crash_match(make_crash(timed_out=True), target)
        assert not strict_crash_match(make_crash(oom_killed=True), target)

    def test_clean_run_never_matches(self):
        from helpers import make_clean

        assert not strict_crash_match(make_clean(), crash_signature(make_crash()))
