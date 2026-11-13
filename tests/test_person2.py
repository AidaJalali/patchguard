import json
import subprocess

import pytest
from helpers import make_clean, make_crash

from classifier.verdict import classify_pair
from correlator.correlator import DiffCorrelation, correlate
from diff_parser.diff_analyzer import (
    DiffError,
    FileDiff,
    FunctionSpan,
    Hunk,
    PatchDiff,
    analyze_git,
    analyze_sources,
    extract_functions,
    parse_hunks,
)
from models import (
    ReplayReport,
    ReplayResult,
    ReproducerArtifact,
    StackFrame,
    crash_signature,
)
from oracle.functional_oracle import (
    OracleError,
    OracleExpectation,
    evaluate,
    evaluate_suite,
    load_oracle,
)
from reporter.report_gen import write_reports


def patch_fixture():
    return PatchDiff(
        [
            FileDiff(
                "src/parse.c",
                [Hunk(40, 3, 40, 3)],
                [
                    FunctionSpan("src/parse.c", "copy_data", 35, 50, ("helper",)),
                    FunctionSpan("src/parse.c", "helper", 60, 70),
                ],
                [
                    FunctionSpan("src/parse.c", "copy_data", 35, 50, ("helper",)),
                    FunctionSpan("src/parse.c", "helper", 60, 70),
                ],
            )
        ]
    )


def replay(result, fid="f"):
    return ReplayReport(
        fid,
        [
            ReplayResult(
                i,
                True,
                True,
                error_type=result.error_type,
                signature=crash_signature(result),
            )
            for i in range(1, 4)
        ],
        True,
        False,
        test_id=result.test_id,
        version=result.version,
        build_type=result.build_type,
    )


def reference(valid=False, exit_code=0):
    return OracleExpectation("t1", exit_code, valid, "exact", "")


def pair(status):
    base, patched = make_crash(), make_clean(version="patched", stdout="")
    if status == "New Issue":
        base, patched = make_clean(stdout=""), make_crash(version="patched")
    elif status == "Incomplete Fix":
        patched = make_crash(version="patched")
    elif status == "Functional Regression":
        base, patched = (
            make_clean(stdout=""),
            make_clean(version="patched", stdout="wrong"),
        )
    return base, patched


class TestDiff:
    def test_hunks_default_and_zero_counts(self):
        assert parse_hunks("@@ -2 +3 @@\n@@ -5,0 +7,2 @@\n@@ -9,2 +8,0 @@") == [
            Hunk(2, 1, 3, 1),
            Hunk(5, 0, 7, 2),
            Hunk(9, 2, 8, 0),
        ]
        assert Hunk(5, 0, 7, 2).interval("base") is None

    def test_pure_insertion_hunk_marks_insertion_point_function(self):


        change = FileDiff(
            "vuln.c",
            [Hunk(7, 0, 8, 3)],
            [FunctionSpan("vuln.c", "main", 5, 14)],
            [FunctionSpan("vuln.c", "main", 5, 17)],
        )
        assert [f.name for f in change.modified_functions("base")] == ["main"]
        assert [f.name for f in change.modified_functions("patched")] == ["main"]

    def test_pure_deletion_hunk_marks_insertion_point_function(self):
        change = FileDiff(
            "vuln.c",
            [Hunk(7, 3, 7, 0)],
            [FunctionSpan("vuln.c", "main", 5, 14)],
            [FunctionSpan("vuln.c", "main", 5, 11)],
        )
        assert [f.name for f in change.modified_functions("base")] == ["main"]
        assert [f.name for f in change.modified_functions("patched")] == ["main"]

    def test_graph_only_files_do_not_poison_diagnostics(self, monkeypatch):



        from diff_parser import diff_analyzer

        real_extract = diff_analyzer.extract_functions

        def flaky_extract(source, **kwargs):
            if "unity.c" in str(kwargs.get("file", "")):
                raise DiffError("AST analysis failed for unity.c: missing include")
            return real_extract(source, **kwargs)

        monkeypatch.setattr(diff_analyzer, "extract_functions", flaky_extract)
        changes = {
            "changed.c": (
                "int main(void) { return 0; }\n",
                "int main(void) { return 1; }\n",
                "@@ -1 +1 @@\n-int main(void) { return 0; }\n"
                "+int main(void) { return 1; }\n",
            ),
            "tests/unity.c": (
                "int helper(void) { return 1; }\n",
                "int helper(void) { return 1; }\n",
                "",
            ),
        }
        patch = diff_analyzer.analyze_sources(changes)
        assert patch.diagnostics == []
        assert {f.path for f in patch.files} == {"changed.c", "tests/unity.c"}
        changed = next(f for f in patch.files if f.path == "changed.c")
        assert [f.name for f in changed.modified_functions("base")] == ["main"]

    def test_real_c_ast_ignores_comments_strings_and_declarations(self):
        source = """// int fake() { }
const char *s = "int bogus() { }";
int declared(int);
int helper(int x) { return x; }
int parse(int x) {
 return helper(x);
}
"""
        spans = extract_functions(source, file="x.c")
        assert [(f.name, f.start_line, f.end_line) for f in spans] == [
            ("helper", 4, 4),
            ("parse", 5, 7),
        ]
        assert spans[1].calls == ("helper",)

    def test_cpp_methods_and_overloads(self):
        functions = extract_functions(
            "namespace N { int f(int x) { return x; } int f() { return 1; } }\n"
            "struct S { int method() const { return N::f(1); } };",
            file="target.cpp",
        )
        assert [f.name for f in functions] == ["f", "f", "method"]
        assert functions[-1].calls == ("f",)
        patch = PatchDiff([FileDiff("target.cpp", [], [], functions)])
        assert patch.call_graph("patched")[functions[-1].key] == {functions[0].key}

    def test_utf8_byte_offsets(self):
        spans = extract_functions("// فارسی\nint f() { return 0; }", file="x.c")
        assert spans[0].start_line == 2

    def test_ast_failure_is_explicit(self):
        with pytest.raises(DiffError):
            extract_functions("int f( {", file="x.c")
        patch = analyze_sources({"x.c": ("int f( {", None, "@@ -1 +0,0 @@")})
        assert patch.diagnostics
        assert not correlate("f", make_crash(), patch).proven

    def test_graph_two_hops_and_deletion_mapping(self):
        functions = [
            FunctionSpan("x.c", "a", 1, 3, ("b",)),
            FunctionSpan("x.c", "b", 5, 7, ("c",)),
            FunctionSpan("x.c", "c", 9, 11),
        ]
        patch = PatchDiff([FileDiff("x.c", [Hunk(2, 1, 2, 0)], functions, functions)])
        assert [f.name for f in patch.modified_functions("base")] == ["a"]


        assert [f.name for f in patch.modified_functions("patched")] == ["a"]
        assert functions[2].key not in patch.neighborhood("base", 1)
        assert functions[2].key in patch.neighborhood("base", 2)

    def test_git_snapshots_no_checkout_and_paths_with_spaces(self, tmp_path):
        def git(*args):
            return (
                subprocess.check_output(
                    ["git", "-C", str(tmp_path), *args], stderr=subprocess.STDOUT
                )
                .decode()
                .strip()
            )

        git("init", "-q")
        git("config", "user.email", "fixture@example.test")
        git("config", "user.name", "Fixture")
        path = tmp_path / "source with space.c"
        path.write_text("int f() { return 0; }\n")
        git("add", ".")
        git("commit", "-qm", "base")
        base = git("rev-parse", "HEAD")
        path.write_text("int f() { return 1; }\n")
        git("commit", "-qam", "patched")
        patched = git("rev-parse", "HEAD")
        path.write_text("uncommitted")
        analysis = analyze_git(tmp_path, base, patched)
        assert analysis.files[0].path == "source with space.c"
        assert analysis.modified_functions("base")[0].name == "f"
        assert path.read_text() == "uncommitted"
        with pytest.raises(DiffError):
            analyze_git(tmp_path, "--help", patched)


class TestCorrelation:
    def test_direct_frame(self):
        match = correlate("f", make_crash(), patch_fixture())
        assert match.correlation_confidence == "HIGH"
        assert match.matched_functions == ["copy_data"]

    def test_runtime_caller_frame(self):
        result = make_crash(
            stack_trace=[
                StackFrame(0, "memcpy"),
                StackFrame(1, "copy_data", "src/parse.c", 42),
            ]
        )
        assert correlate("f", result, patch_fixture()).mechanism == "stack_frame"

    def test_static_callee(self):
        assert (
            correlate(
                "f", make_crash(function="helper", line=65), patch_fixture()
            ).mechanism
            == "call_graph"
        )

    def test_unrelated_and_wrong_file_are_unproven(self):
        for result in (make_crash(function="other"), make_crash(file="other.c")):
            assert not correlate("f", result, patch_fixture()).proven

    def test_line_proximity_alone_is_not_evidence(self):
        assert not correlate(
            "f", make_crash(function="unrelated", line=42), patch_fixture()
        ).proven

    def test_allocation_frame(self):
        result = make_crash(function="malloc", file="lib.c")
        assert (
            correlate(
                "f",
                result,
                patch_fixture(),
                extra_frames=(StackFrame(0, "copy_data", "src/parse.c", 42),),
            ).mechanism
            == "direct_frame"
        )

    def test_differential_coverage(self):
        result = make_crash(function="other")
        assert (
            correlate(
                "f",
                result,
                patch_fixture(),
                base_coverage={("src/parse.c", 10)},
                patched_coverage={("src/parse.c", 42)},
            ).mechanism
            == "differential_coverage"
        )
        assert not correlate(
            "f",
            result,
            patch_fixture(),
            base_coverage={("src/parse.c", 42)},
            patched_coverage={("src/parse.c", 42)},
        ).proven

    def test_ambiguous_function_name(self):
        patch = patch_fixture()
        patch.files.append(
            FileDiff("other.c", [], [FunctionSpan("other.c", "copy_data", 35, 50)], [])
        )
        assert not correlate("f", make_crash(file=None), patch).proven


class TestOracle:
    @pytest.mark.parametrize(
        "kind,value,stdout,passed",
        [
            ("exact", "ok\n", "ok\n", True),
            ("exact", "ok\n", "ok", False),
            ("regex", r"count=\d+\n", "count=12\n", True),
            ("regex", r"count=\d+", "junk count=12", False),
            ("json", {"a": 1, "b": [2]}, '{"b":[2],"a":1}', True),
            ("json", {"a": True}, '{"a":1}', False),
            ("json", None, "null", True),
            ("json", None, "NaN", False),
        ],
    )
    def test_stdout_matchers(self, kind, value, stdout, passed):
        expect = OracleExpectation("t1", 0, True, kind, value)
        assert evaluate(make_clean(stdout=stdout), expect).passed is passed

    def test_nonzero_valid_rejection_and_stderr(self):
        expect = OracleExpectation("t1", 2, False, "exact", "", "invalid")
        assert evaluate(
            make_clean(exit_code=2, stdout="", stderr="invalid input"), expect
        ).passed
        assert not evaluate(
            make_clean(exit_code=2, stdout="", stderr="other"), expect
        ).passed

    @pytest.mark.parametrize("flag", ["crashed", "timed_out", "oom_killed"])
    def test_limits_never_pass(self, flag):
        assert not evaluate(make_clean(stdout="", **{flag: True}), reference()).passed

    def test_load_and_missing_matrix(self, tmp_path):
        path = tmp_path / "oracle.json"
        path.write_text(
            json.dumps(
                {
                    "reference_source": "independent reference tests",
                    "tests": [
                        {
                            "test_id": "t1",
                            "expected_exit_code": 0,
                            "is_valid_input": True,
                            "expected_stdout_exact": "ok",
                        }
                    ],
                }
            )
        )
        suite = load_oracle(path)
        with pytest.raises(OracleError, match="missing"):
            evaluate_suite([], suite)
        results = [
            make_clean(version=v, build_type=b)
            for v in ("base", "patched")
            for b in ("release", "sanitized")
        ]
        assert all(r.passed for r in evaluate_suite(results, suite))
        with pytest.raises(OracleError, match="duplicate"):
            evaluate_suite(results + results, suite)

    @pytest.mark.parametrize(
        "row",
        [
            {"expected_exit_code": True},
            {"is_valid_input": "true"},
            {"expected_stdout_regex": "["},
            {"expected_stdout_regex": ".*", "expected_stdout_exact": "ok"},
        ],
    )
    def test_bad_oracle_rejected(self, tmp_path, row):
        entry = {
            "test_id": "t1",
            "expected_exit_code": 0,
            "is_valid_input": True,
            "expected_stdout_exact": "ok",
        }
        if "expected_stdout_regex" in row and "expected_stdout_exact" not in row:
            entry.pop("expected_stdout_exact")
        entry.update(row)
        path = tmp_path / "ref.json"
        path.write_text(
            json.dumps({"reference_source": "specification", "tests": [entry]})
        )
        with pytest.raises(OracleError):
            load_oracle(path)


class TestClassifier:
    @pytest.mark.parametrize(
        "status", ["Fixed", "Incomplete Fix", "New Issue", "Functional Regression"]
    )
    def test_required_statuses(self, status):
        base, patched = pair(status)
        correlation = correlate("f", base if base.crashed else patched, patch_fixture())
        if status == "Functional Regression":
            correlation = DiffCorrelation("f", "INCONCLUSIVE")
        expected = reference(valid=status == "Functional Regression")
        verdict = classify_pair(
            "f",
            base,
            patched,
            correlation=correlation,
            base_oracle=evaluate(base, expected),
            patched_oracle=evaluate(patched, expected),
            base_replay=replay(base) if base.crashed else None,
            patched_replay=replay(patched) if patched.crashed else None,
        )
        assert verdict.status == status

    def test_no_crash_does_not_prove_fixed(self):
        base, patched = pair("Fixed")
        result = classify_pair(
            "f",
            base,
            patched,
            correlation=correlate("f", base, patch_fixture()),
            base_replay=replay(base),
        )
        assert result.status == "Inconclusive"

    def test_unrelated_and_flaky_inconclusive(self):
        base, patched = pair("Fixed")
        for correlation in (
            DiffCorrelation("f", "INCONCLUSIVE"),
            correlate("f", base, patch_fixture()),
        ):
            artifact = ReproducerArtifact("f", "bundle", "3/3", True, 13, 13, "input")
            result = classify_pair(
                "f",
                base,
                patched,
                correlation=correlation,
                base_replay=replay(base),
                patched_oracle=evaluate(patched, reference()),
                base_artifact=artifact,
            )
            assert result.status == "Inconclusive"

    @pytest.mark.parametrize("flag", ["timed_out", "oom_killed"])
    def test_resource_limits_inconclusive(self, flag):
        base, patched = pair("Fixed")
        setattr(patched, flag, True)
        assert (
            classify_pair(
                "f",
                base,
                patched,
                correlation=correlate("f", base, patch_fixture()),
                base_replay=replay(base),
            ).status
            == "Inconclusive"
        )

    def test_mixed_build_or_test_rejected(self):
        base, patched = pair("Fixed")
        patched.build_type = "release"
        with pytest.raises(ValueError):
            classify_pair("f", base, patched, correlation=DiffCorrelation("f", "HIGH"))
        patched.build_type = base.build_type
        patched.test_id = "another"
        with pytest.raises(ValueError):
            classify_pair("f", base, patched, correlation=DiffCorrelation("f", "HIGH"))

    def test_release_replay_cannot_certify_sanitized_finding(self):
        base, patched = pair("Fixed")
        confirmed = replay(base)
        confirmed.build_type = "release"
        with pytest.raises(ValueError, match="does not match the execution"):
            classify_pair(
                "f",
                base,
                patched,
                correlation=correlate("f", base, patch_fixture()),
                base_replay=confirmed,
                patched_oracle=evaluate(patched, reference()),
            )

    def test_base_replay_cannot_certify_patched_crash(self):
        base, patched = pair("Incomplete Fix")
        confirmed = replay(patched)
        confirmed.version = "base"
        with pytest.raises(ValueError, match="does not match the execution"):
            classify_pair(
                "f",
                base,
                patched,
                correlation=correlate("f", base, patch_fixture()),
                base_replay=replay(base),
                patched_replay=confirmed,
            )

    def test_replay_from_another_test_is_rejected(self):
        base, patched = pair("Fixed")
        confirmed = replay(base)
        confirmed.test_id = "other-test"
        with pytest.raises(ValueError, match="does not match the execution"):
            classify_pair(
                "f",
                base,
                patched,
                correlation=correlate("f", base, patch_fixture()),
                base_replay=confirmed,
                patched_oracle=evaluate(patched, reference()),
            )

    def test_missing_provenance_never_confirms(self):
        base, patched = pair("Fixed")
        confirmed = ReplayReport(
            "f",
            [
                ReplayResult(
                    1,
                    True,
                    True,
                    error_type=base.error_type,
                    signature=crash_signature(base),
                )
            ],
            True,
            False,
        )
        verdict = classify_pair(
            "f",
            base,
            patched,
            correlation=correlate("f", base, patch_fixture()),
            base_replay=confirmed,
            patched_oracle=evaluate(patched, reference()),
        )
        assert verdict.status == "Inconclusive"

    def test_matching_provenance_still_confirms(self):
        base, patched = pair("Fixed")
        verdict = classify_pair(
            "f",
            base,
            patched,
            correlation=correlate("f", base, patch_fixture()),
            base_replay=replay(base),
            patched_oracle=evaluate(patched, reference()),
        )
        assert verdict.status == "Fixed"

    def test_changed_crash_is_not_automatically_new_issue(self):
        base, patched = pair("Incomplete Fix")
        patched.error_type = "heap-use-after-free"
        assert (
            classify_pair(
                "f",
                base,
                patched,
                correlation=correlate("f", patched, patch_fixture()),
                base_replay=replay(base),
                patched_replay=replay(patched),
            ).status
            == "Inconclusive"
        )

    def test_independent_findings_survive_report_gate(self, tmp_path):
        findings = []
        for i, status in enumerate(("New Issue", "Functional Regression")):
            fid = f"f{i}"
            base, patched = pair(status)
            expected = reference(valid=status == "Functional Regression")
            findings.append(
                classify_pair(
                    fid,
                    base,
                    patched,
                    correlation=correlate(fid, patched, patch_fixture()),
                    base_oracle=evaluate(base, expected),
                    patched_oracle=evaluate(patched, expected),
                    patched_replay=replay(patched, fid) if patched.crashed else None,
                ).to_dict()
            )
        report = write_reports(
            {"target_name": "fixture", "findings": findings},
            tmp_path / "report.json",
            tmp_path / "SUMMARY.md",
        )
        assert report["exit_code"] == 10
        assert [f["status"] for f in report["findings"]] == [
            "New Issue",
            "Functional Regression",
        ]


def test_address_taken_is_not_a_direct_call():
    source = "int helper(void) { return 1; }\nint caller(void) { int (*p)(void) = helper; return p(); }"
    functions = extract_functions(source, file="x.c")
    assert functions[1].calls == ()


def test_git_cross_file_graph_and_versioned_headers(tmp_path):
    def git(*args):
        return (
            subprocess.check_output(
                ["git", "-C", str(tmp_path), *args], stderr=subprocess.STDOUT
            )
            .decode()
            .strip()
        )

    git("init", "-q")
    git("config", "user.email", "fixture@example.test")
    git("config", "user.name", "Fixture")
    (tmp_path / "api.h").write_text("int helper(int);\n#define LIMIT 8\n")
    (tmp_path / "helper.c").write_text(
        '#include "api.h"\nint helper(int n) { return n; }\n'
    )
    source = tmp_path / "caller.c"
    source.write_text('#include "api.h"\nint caller(int n) { return helper(n); }\n')
    git("add", ".")
    git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    source.write_text(
        '#include "api.h"\nint caller(int n) { return n < LIMIT ? helper(n) : -1; }\n'
    )
    git("commit", "-qam", "patch")
    patch = analyze_git(tmp_path, base, "HEAD")
    assert not patch.diagnostics
    caller = next(f for f in patch.functions("patched") if f.name == "caller")
    helper = next(f for f in patch.functions("patched") if f.name == "helper")
    assert helper.key in patch.call_graph("patched")[caller.key]
    result = make_crash(function="helper", file="helper.c", line=2, version="patched")
    assert correlate("f", result, patch).mechanism == "call_graph"


def test_real_c_execution_to_classifier_and_person4_report(tmp_path):

    from models import ExecutionResult
    from reproducer.bundler import verify_reproducibility

    base_source = """#include <stdio.h>
int main(void) {
 int c = getchar();
 if (c == 'X') { volatile int *p = 0; *p = 1; }
 return 0;
}
"""
    patched_source = base_source.replace("volatile int *p = 0; *p = 1;", "return 2;")
    binaries = {}
    for version, source in (("base", base_source), ("patched", patched_source)):
        path = tmp_path / f"{version}.c"
        path.write_text(source)
        binary = tmp_path / version
        subprocess.run(
            ["gcc", "-O0", str(path), "-o", str(binary)],
            check=True,
            capture_output=True,
        )
        binaries[version] = binary
    patch = analyze_sources({"target.c": (base_source, patched_source, "@@ -4 +4 @@")})
    assert not patch.diagnostics

    class FixtureRunner:
        def run(self, input_bytes, *, version, build_type, timeout_sec):
            process = subprocess.run(
                [str(binaries[version])],
                input=input_bytes,
                capture_output=True,
                timeout=timeout_sec,
            )
            crashed = process.returncode < 0
            return ExecutionResult(
                "t1",
                version,
                build_type,
                process.returncode,
                signal=-process.returncode if crashed else None,
                crashed=crashed,
                error_type="null-dereference" if crashed else None,
                detection_mechanism="OS_SIGNAL" if crashed else None,
                stack_trace=[StackFrame(0, "main", "target.c", 4)] if crashed else [],
                stdout=process.stdout.decode(),
                stderr=process.stderr.decode(),
            )

    runner = FixtureRunner()
    base = runner.run(b"X", version="base", build_type="release", timeout_sec=5)
    patched = runner.run(b"X", version="patched", build_type="release", timeout_sec=5)
    confirmed = verify_reproducibility(runner, b"X", base, finding_id="real")
    verdict = classify_pair(
        "real",
        base,
        patched,
        correlation=correlate("real", base, patch),
        base_replay=confirmed,
        patched_oracle=evaluate(patched, reference(exit_code=2)),
    )
    assert verdict.status == "Fixed"
    report = write_reports(
        {
            "target_name": "real-C-interface-test",
            "findings": [verdict.to_dict()],
            "base_bug_reproduced": True,
            "patch_fix_verified": True,
            "functional_tests_passed": False,
            "mandatory_checks_complete": False,
        },
        tmp_path / "report.json",
        tmp_path / "SUMMARY.md",
    )
    assert report["exit_code"] == 40


def test_classifier_uses_shared_replay_matching_with_optional_source_info():
    from models import CrashSignature

    base, patched = pair("Fixed")
    confirmed = replay(base)
    confirmed.results[0].signature = CrashSignature(
        base.error_type, "copy_data", None, None
    )
    verdict = classify_pair(
        "f",
        base,
        patched,
        correlation=correlate("f", base, patch_fixture()),
        base_replay=confirmed,
        patched_oracle=evaluate(patched, reference()),
    )
    assert verdict.status == "Fixed"
    confirmed.results[0].signature = CrashSignature(
        base.error_type, "unrelated", None, None
    )
    assert (
        classify_pair(
            "f",
            base,
            patched,
            correlation=correlate("f", base, patch_fixture()),
            base_replay=confirmed,
            patched_oracle=evaluate(patched, reference()),
        ).status
        == "Inconclusive"
    )


def test_duplicate_replay_attempts_cannot_confirm_a_fix():
    base, patched = pair("Fixed")
    confirmed = replay(base)
    confirmed.results[1].attempt = 1
    assert (
        classify_pair(
            "f",
            base,
            patched,
            correlation=correlate("f", base, patch_fixture()),
            base_replay=confirmed,
            patched_oracle=evaluate(patched, reference()),
        ).status
        == "Inconclusive"
    )


def test_external_call_never_resolves_to_another_files_static_function():
    changed = "extern int helper(int);\nint changed(int x) { return helper(x); }\n"
    patched = changed.replace("helper(x)", "helper(x + 1)")
    unrelated = "static int helper(int x) { return x; }\nint other(int x) { return helper(x); }\n"
    patch = analyze_sources(
        {
            "changed.c": (changed, patched, "@@ -2 +2 @@"),
            "unrelated.c": (unrelated, unrelated, ""),
        }
    )
    assert not patch.diagnostics
    functions = patch.functions("patched")
    changed_fn = next(f for f in functions if f.name == "changed")
    helper = next(f for f in functions if f.name == "helper")
    other = next(f for f in functions if f.name == "other")
    assert helper.linkage == "internal"
    assert patch.call_graph("patched")[changed_fn.key] == set()
    assert patch.call_graph("patched")[other.key] == {helper.key}
    result = make_crash(
        function="helper", file="unrelated.c", line=1, version="patched"
    )
    assert not correlate("f", result, patch).proven


def test_real_external_definition_remains_resolvable_despite_static_namesake():
    caller = "extern int helper(int);\nint changed(int x) { return helper(x); }\n"
    external = "int helper(int x) { return x; }\n"
    internal = "static int helper(int x) { return x; }\nint other(int x) { return helper(x); }\n"
    patch = analyze_sources(
        {
            "caller.c": (caller, caller, "@@ -2 +2 @@"),
            "external.c": (external, external, ""),
            "internal.c": (internal, internal, ""),
        }
    )
    assert not patch.diagnostics
    caller_fn = next(f for f in patch.functions("patched") if f.name == "changed")
    target = next(f for f in patch.functions("patched") if f.file == "external.c")
    assert patch.call_graph("patched")[caller_fn.key] == {target.key}


def test_cpp_symbols_do_not_cross_namespaces_or_anonymous_linkage():
    caller = (
        "namespace N { int helper(int); }\nint caller(int x) { return N::helper(x); }\n"
    )
    unrelated = "namespace Other { int helper(int x) { return x; } }\n"
    private = "namespace { int helper(int x) { return x; } }\nint other(int x) { return helper(x); }\n"
    patch = analyze_sources(
        {
            "caller.cpp": (caller, caller, "@@ -2 +2 @@"),
            "other.cpp": (unrelated, unrelated, ""),
            "private.cpp": (private, private, ""),
        }
    )
    assert not patch.diagnostics
    functions = patch.functions("patched")
    caller_fn = next(f for f in functions if f.name == "caller")
    private_fn = next(
        f for f in functions if f.file == "private.cpp" and f.name == "helper"
    )
    assert private_fn.linkage == "internal"
    assert patch.call_graph("patched")[caller_fn.key] == set()
