import pytest
from helpers import MockRunner, make_clean, make_crash

from minimizer.ddmin import CrashSignaturePredicate, ddmin


class TestDdminAlgorithm:
    def test_reduces_to_single_marker(self):
        initial = b"x" * 4096 + b"PWNME" + b"y" * 4096
        result = ddmin(initial, lambda b: b"PWNME" in b)
        assert result == b"PWNME"

    def test_preserves_all_required_parts(self):
        initial = b"....ab....cd...."
        result = ddmin(initial, lambda b: b"ab" in b and b"cd" in b)
        assert b"ab" in result and b"cd" in result
        assert len(result) <= 4

    def test_raises_when_initial_fails(self):
        with pytest.raises(ValueError, match="does not satisfy"):
            ddmin(b"abc", lambda b: False)

    def test_already_minimal_input_returns_unchanged(self):
        assert ddmin(b"PWN", lambda b: b"PWN" in b) == b"PWN"

    def test_max_iterations_budgets_work(self):
        calls = []

        def predicate(b: bytes) -> bool:
            calls.append(b)
            return b"Z" in b

        initial = b"Z" + b"x" * 1000
        result = ddmin(initial, predicate, max_iterations=1)
        assert b"Z" in result
        assert len(result) < len(initial)
        assert len(calls) <= len(initial)

    def test_empty_input_handled(self):
        assert ddmin(b"ab", lambda b: len(b) <= 2) in (b"ab", b"a", b"b", b"")

    def test_one_byte_input_reduces_to_empty(self):

        assert ddmin(b"A", lambda b: True) == b""

    def test_one_byte_input_unchanged_when_empty_rejected(self):
        assert ddmin(b"A", lambda b: b) == b"A"

    def test_empty_initial_input_works(self):
        assert ddmin(b"", lambda b: True) == b""
        assert ddmin(b"", lambda b: len(b) == 0) == b""


class TestCrashSignaturePredicate:
    def test_accepts_identical_signature(self):
        runner = MockRunner(default=lambda _: make_crash())
        predicate = CrashSignaturePredicate(runner, make_crash())
        assert predicate(b"candidate") is True
        assert predicate.runs == 1

    def test_rejects_clean_run(self):
        runner = MockRunner(default=lambda _: make_clean())
        predicate = CrashSignaturePredicate(runner, make_crash())
        assert predicate(b"candidate") is False

    def test_rejects_different_error_type(self):
        runner = MockRunner(default=lambda _: make_crash(error_type="null-dereference"))
        predicate = CrashSignaturePredicate(runner, make_crash())
        assert predicate(b"candidate") is False

    def test_rejects_different_crash_location(self):
        runner = MockRunner(default=lambda _: make_crash(line=43))
        predicate = CrashSignaturePredicate(runner, make_crash())
        assert predicate(b"candidate") is False

    def test_lax_mode_matches_error_type_only(self):
        runner = MockRunner(default=lambda _: make_crash(line=43))
        predicate = CrashSignaturePredicate(runner, make_crash(), strict=False)
        assert predicate(b"candidate") is True

    def test_rejects_timeout_even_with_matching_crash_flags(self):

        runner = MockRunner(default=lambda _: make_crash(timed_out=True))
        predicate = CrashSignaturePredicate(runner, make_crash())
        assert predicate(b"candidate") is False

    def test_rejects_oom_even_with_matching_crash_flags(self):
        runner = MockRunner(default=lambda _: make_crash(oom_killed=True))
        predicate = CrashSignaturePredicate(runner, make_crash())
        assert predicate(b"candidate") is False

    def test_rejects_candidate_without_crash_evidence(self):

        runner = MockRunner(
            default=lambda _: make_crash(error_type=None, stack_trace=[])
        )
        predicate = CrashSignaturePredicate(runner, make_crash())
        assert predicate(b"candidate") is False

    def test_rejects_when_original_has_insufficient_evidence(self):
        runner = MockRunner(
            default=lambda _: make_crash(error_type=None, stack_trace=[])
        )
        predicate = CrashSignaturePredicate(
            runner, make_crash(error_type=None, stack_trace=[])
        )
        assert predicate(b"candidate") is False

    def test_accepts_frame_without_line_info(self):

        runner = MockRunner(default=lambda _: make_crash(line=7))
        predicate = CrashSignaturePredicate(runner, make_crash(line=None))
        assert predicate(b"candidate") is True

    def test_uses_original_version_and_build_type(self):
        seen = {}
        original = make_crash(version="patched", build_type="release")

        def run(input_bytes, *, version, build_type, timeout_sec):
            seen.update(version=version, build_type=build_type, timeout_sec=timeout_sec)

            return make_crash(version=version, build_type=build_type)

        runner = MockRunner(default=lambda _: make_crash())
        runner.run = run
        predicate = CrashSignaturePredicate(runner, original)
        assert predicate(b"candidate") is True
        assert seen == {
            "version": "patched",
            "build_type": "release",
            "timeout_sec": 5.0,
        }


class TestContextEnforcement:
    def test_wrong_version_rejected(self):
        runner = MockRunner(default=lambda _: make_crash(version="patched"))
        predicate = CrashSignaturePredicate(runner, make_crash())
        with pytest.raises(ValueError, match="execution context mismatch"):
            predicate(b"candidate")

    def test_wrong_build_type_rejected(self):
        runner = MockRunner(default=lambda _: make_crash(build_type="release"))
        predicate = CrashSignaturePredicate(runner, make_crash())
        with pytest.raises(ValueError, match="execution context mismatch"):
            predicate(b"candidate")

    def test_wrong_test_id_rejected(self):
        runner = MockRunner(default=lambda _: make_crash(test_id="other"))
        predicate = CrashSignaturePredicate(runner, make_crash())
        with pytest.raises(ValueError, match="execution context mismatch"):
            predicate(b"candidate")

    def test_lax_mode_also_rejects_wrong_context(self):
        runner = MockRunner(default=lambda _: make_crash(version="patched"))
        predicate = CrashSignaturePredicate(runner, make_crash(), strict=False)
        with pytest.raises(ValueError, match="execution context mismatch"):
            predicate(b"candidate")

    def test_constructor_refuses_mixed_context(self):
        for overrides in (
            {"version": "patched"},
            {"build_type": "release"},
            {"test_id": "other"},
        ):
            with pytest.raises(ValueError, match="cannot reuse the crash signature"):
                CrashSignaturePredicate(MockRunner(), make_crash(), **overrides)

    def test_no_escape_hatch_exists_for_context_changes(self):

        original = make_crash()
        for overrides in (
            {"version": "patched"},
            {"build_type": "release"},
            {"test_id": "other"},
        ):
            with pytest.raises(ValueError, match="cannot reuse the crash signature"):
                CrashSignaturePredicate(MockRunner(), original, **overrides)

    def test_new_baseline_from_real_execution_works(self):

        new_baseline = make_crash(version="patched", build_type="release", test_id="t2")
        runner = MockRunner(
            default=lambda _: make_crash(
                version="patched", build_type="release", test_id="t2"
            )
        )
        predicate = CrashSignaturePredicate(runner, new_baseline)
        assert predicate(b"candidate") is True

    def test_new_baseline_still_enforces_returned_context(self):
        new_baseline = make_crash(version="patched", build_type="release", test_id="t2")
        runner = MockRunner(default=lambda _: make_crash(version="base"))
        predicate = CrashSignaturePredicate(runner, new_baseline)
        with pytest.raises(ValueError, match="execution context mismatch"):
            predicate(b"candidate")


class TestDdminWithCrashPredicate:
    def test_minimizes_to_crashing_marker(self):

        runner = MockRunner(
            default=lambda inp: make_crash() if b"PWN" in inp else make_clean()
        )
        predicate = CrashSignaturePredicate(runner, make_crash())
        initial = b"A" * 200 + b"PWN" + b"B" * 200
        result = ddmin(initial, predicate)
        assert result == b"PWN"

    def test_does_not_shrink_below_crash_signature(self):

        runner = MockRunner(
            default=lambda inp: (
                make_crash()
                if b"PWN" in inp
                else make_crash(error_type="stack-buffer-overflow", line=99)
                if b"BAD" in inp
                else make_clean()
            )
        )
        predicate = CrashSignaturePredicate(runner, make_crash())
        initial = b"BAD" + b"x" * 50 + b"PWN"
        result = ddmin(initial, predicate)
        assert b"PWN" in result
        assert result == b"PWN"
