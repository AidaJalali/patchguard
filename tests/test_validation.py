from __future__ import annotations

import resource
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from builder.builder import DualBuilder
from conftest import requires_docker
from validation import run_validation

VULN_C = textwrap.dedent(
    """
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char **argv) {
        if (argc < 2) { fprintf(stderr, "usage\\n"); return 1; }
        if (strcmp(argv[1], "hang") == 0) { for (;;) {} }
        char *buf = (char *)malloc(8);
        if (!buf) return 2;
        strcpy(buf, argv[1]);
        printf("ok:%s\\n", buf);
        free(buf);
        return 0;
    }
    """
).lstrip()

CORRECT_C = textwrap.dedent(
    """
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char **argv) {
        if (argc < 2) { fprintf(stderr, "usage\\n"); return 1; }
        if (strcmp(argv[1], "hang") == 0) { for (;;) {} }
        if (strlen(argv[1]) >= 8) { fprintf(stderr, "input too long\\n"); return 1; }
        char *buf = (char *)malloc(8);
        if (!buf) return 2;
        memcpy(buf, argv[1], strlen(argv[1]) + 1);
        printf("ok:%s\\n", buf);
        free(buf);
        return 0;
    }
    """
).lstrip()

INCOMPLETE_C = textwrap.dedent(
    """
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char **argv) {
        if (argc < 2) { fprintf(stderr, "usage\\n"); return 1; }
        if (strcmp(argv[1], "hang") == 0) { for (;;) {} }
        if (strncmp(argv[1], "AAAA", 4) == 0 && strlen(argv[1]) >= 8) {
            fprintf(stderr, "input too long\\n"); return 1;
        }
        char *buf = (char *)malloc(8);
        if (!buf) return 2;
        strcpy(buf, argv[1]);
        printf("ok:%s\\n", buf);
        free(buf);
        return 0;
    }
    """
).lstrip()

REGRESSION_C = textwrap.dedent(
    """
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char **argv) {
        if (argc < 2) { fprintf(stderr, "usage\\n"); return 1; }
        if (strcmp(argv[1], "hang") == 0) { for (;;) {} }
        if (strlen(argv[1]) >= 4) { fprintf(stderr, "input too long\\n"); return 1; }
        char *buf = (char *)malloc(8);
        if (!buf) return 2;
        memcpy(buf, argv[1], strlen(argv[1]) + 1);
        printf("ok:%s\\n", buf);
        free(buf);
        return 0;
    }
    """
).lstrip()

NEW_ISSUE_C = textwrap.dedent(
    """
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char **argv) {
        if (argc < 2) { fprintf(stderr, "usage\\n"); return 1; }
        if (strcmp(argv[1], "hang") == 0) { for (;;) {} }
        /* correct fix plus a newly introduced crash */
        if (strlen(argv[1]) >= 8) { fprintf(stderr, "input too long\\n"); return 1; }
        if (strcmp(argv[1], "boom") == 0) { int *p = NULL; *p = 42; }
        char *buf = (char *)malloc(8);
        if (!buf) return 2;
        memcpy(buf, argv[1], strlen(argv[1]) + 1);
        printf("ok:%s\\n", buf);
        free(buf);
        return 0;
    }
    """
).lstrip()


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=str(repo), check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


@pytest.fixture
def scenario_repo(tmp_path: Path) -> dict[str, str]:
    repo = tmp_path / "scenario_target"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@patchguard.local")
    _git(repo, "config", "user.name", "PatchGuard Test")
    (repo / "vuln.c").write_text(VULN_C)
    _git(repo, "add", "vuln.c")
    _git(repo, "commit", "-qm", "base")
    refs = {"base": _git(repo, "rev-parse", "HEAD")}
    for name, source in (("correct", CORRECT_C), ("incomplete", INCOMPLETE_C),
                         ("regression", REGRESSION_C), ("new_issue", NEW_ISSUE_C)):
        _git(repo, "checkout", "-q", "-b", name, refs["base"])
        (repo / "vuln.c").write_text(source)
        _git(repo, "add", "vuln.c")
        _git(repo, "commit", "-qm", name)
        refs[name] = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "main")
    (repo / ".patchguard_refs").write_text(
        f"{refs['base']}\n{refs['correct']}\n{refs['incomplete']}\n{refs['regression']}\n"
    )
    refs["repo"] = str(repo)
    return refs


def _config(tmp_path: Path, refs: dict, patched: str, **overrides) -> Path:
    data = {
        "target_name": "scenario",
        "repo_path": refs["repo"],
        "base_ref": refs["base"],
        "patched_ref": refs[patched],
        "build_cmd_release": "gcc -O2 -o vuln vuln.c",
        "build_cmd_sanitized": (
            "gcc -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fsanitize=address,undefined "
            "-fno-omit-frame-pointer -g -O1 -o vuln vuln.c"
        ),
        "binary_rel_path": "vuln",
        "input_mode": "args",
        "argv_template": ["{input}"],
        "timeout_sec": 2.0,
        "memory_mb": 256,
        "cpus": 1.0,
        "oracle_source": "scenario fixture expectations (illustrative, for TA approval)",
        "work_dir": str(tmp_path / "work"),
        "output_dir": str(tmp_path / "out"),
        "tests": [
            {"id": "short-ok", "kind": "functional", "input": "hi",
             "expected_exit_code": 0, "is_valid_input": True,
             "stdout_kind": "exact", "stdout_value": "ok:hi\n"},
            {"id": "long-ok", "kind": "functional", "input": "hello",
             "expected_exit_code": 0, "is_valid_input": True,
             "stdout_kind": "exact", "stdout_value": "ok:hello\n"},
            {"id": "boundary-ok", "kind": "boundary", "input": "1234567",
             "expected_exit_code": 0, "is_valid_input": True,
             "stdout_kind": "exact", "stdout_value": "ok:1234567\n"},
            {"id": "poc-overflow", "kind": "security", "input": "AAAAAAAAAAAA",
             "expected_exit_code": 1, "is_valid_input": False,
             "stdout_kind": "none", "stderr_pattern": "input too long",
             "base_expect": {"crash": True},
             "patched_expect": {"crash": False, "exit_code": 1}},
            {"id": "poc-bypass", "kind": "security", "input": "BBBBBBBBBBBB",
             "expected_exit_code": 1, "is_valid_input": False,
             "stdout_kind": "none", "stderr_pattern": "input too long",
             "base_expect": {"crash": True},
             "patched_expect": {"crash": False, "exit_code": 1}},
        ],
    }
    data.update(overrides)
    path = tmp_path / f"config-{patched}.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


@pytest.fixture
def local_transport(monkeypatch):
    def local_build(self, directory, command):
        try:
            subprocess.run(["bash", "-lc", command], cwd=directory, check=True,
                           capture_output=True, timeout=60)
        except subprocess.CalledProcessError as exc:
            from exceptions import ConfigOrBuildError
            raise ConfigOrBuildError(
                code=30,
                message=f"Build failed (exit {exc.returncode}): {exc.stderr}",
            ) from exc

    monkeypatch.setattr(DualBuilder, "_docker_build", local_build)
    monkeypatch.setattr(
        DualBuilder,
        "_verify_elf_x86_64",
        lambda self, p: subprocess.run(["readelf", "-h", str(p)], check=True,
                                       capture_output=True),
    )
    monkeypatch.setattr(
        "runner.sandbox.DockerSandboxRunner.run_raw",
        _local_run_raw,
    )
    monkeypatch.setattr(
        "runner.sandbox.DockerSandboxRunner._gdb_backtrace",
        _local_gdb_backtrace,
    )
    core_limits = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (0, core_limits[1]))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_CORE, core_limits)


def _find_symbolizer() -> str | None:
    import shutil

    candidates = (
        "llvm-symbolizer-18",
        "llvm-symbolizer",
        "/usr/lib/llvm-18/bin/llvm-symbolizer",
    )
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _local_gdb_backtrace(self, artifact, config, input_bytes=None, args=None):
    import shlex
    import tempfile

    try:
        with tempfile.TemporaryDirectory(prefix="patchguard_gdb_local_") as tmp:
            input_file = Path(tmp) / "input.bin"
            input_file.write_bytes(input_bytes if input_bytes is not None else b"")
            argv = [
                a.replace("/work/input.bin", str(input_file)) for a in (args or [])
            ]
            if config.input_mode == "stdin":
                run_expr = "run < " + shlex.quote(str(input_file))
            else:
                run_expr = ("run " + " ".join(shlex.quote(a) for a in argv)).strip()
            proc = subprocess.run(
                ["gdb", "-batch", artifact.binary_path,
                 "-ex", "set pagination off", "-ex", run_expr, "-ex", "bt"],
                capture_output=True, text=True,
                timeout=max(config.timeout_sec * 2, 10),
            )
            return proc.stdout + "\n" + proc.stderr
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _local_run_raw(self, artifact, config, input_bytes=None, args=None):
    symbolizer = _find_symbolizer()
    env = {
        "ASAN_OPTIONS": "detect_leaks=0:symbolize=1",
        "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
    }
    if symbolizer:
        env["ASAN_SYMBOLIZER_PATH"] = symbolizer
    timed_out = False
    try:
        result = subprocess.run(
            [artifact.binary_path, *(args or [])],
            capture_output=True,
            timeout=config.timeout_sec,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        result = subprocess.CompletedProcess(
            exc.cmd, 124, stdout=exc.stdout or b"", stderr=exc.stderr or b"",
        )
    return dict(
        exit_code=result.returncode,
        stdout=result.stdout.decode(),
        stderr=result.stderr.decode(),
        timed_out=timed_out,
        oom_killed=False,
        duration_ms=0,
        cli_command=artifact.binary_path,
    )


def test_local_transport_timeout_preserves_partial_diagnostics():
    result = _local_run_raw(
        None,
        SimpleNamespace(binary_path=sys.executable),
        SimpleNamespace(timeout_sec=0.5),
        args=["-c", "import sys, time; print('started', flush=True); "
              "print('diagnostic', file=sys.stderr, flush=True); time.sleep(30)"],
    )
    assert result["timed_out"] is True
    assert result["exit_code"] == 124
    assert result["stdout"] == "started\n"
    assert result["stderr"] == "diagnostic\n"
    assert result["oom_killed"] is False


def test_local_transport_disables_core_dumps(local_transport):
    result = _local_run_raw(
        None,
        SimpleNamespace(binary_path=sys.executable),
        SimpleNamespace(timeout_sec=2),
        args=["-c", "import resource; "
              "print(resource.getrlimit(resource.RLIMIT_CORE)[0])"],
    )
    assert result["exit_code"] == 0
    assert result["stdout"] == "0\n"
    assert result["timed_out"] is False


def _run(tmp_path: Path, config: Path) -> dict:
    out_json = tmp_path / "report.json"
    out_md = tmp_path / "SUMMARY.md"
    report = run_validation(str(config), str(out_json), str(out_md))
    assert out_json.is_file() and out_md.is_file()
    return report


class TestValidatePipeline:
    def test_correct_scenario_passes(self, tmp_path, scenario_repo, local_transport):
        report = _run(tmp_path, _config(tmp_path, scenario_repo, "correct"))
        assert report["exit_code"] == 0, report
        assert all(report[k] for k in (
            "base_bug_reproduced", "patch_fix_verified",
            "functional_tests_passed", "mandatory_checks_complete"))
        assert any(f["status"] == "Fixed" for f in report["findings"])
        assert report["reproducers"]
        assert all(entry["verified"] for entry in report["regression_entries"])
        assert report["target"]["base_ref"] == scenario_repo["base"]
        assert report["target"]["patched_ref"] == scenario_repo["correct"]
        assert report["target"]["commits"]["base_release"] == scenario_repo["base"]
        assert report["target"]["commits"]["patched_sanitized"] == scenario_repo["correct"]
        assert report["execution_settings"]["timeout_sec"] == 2.0
        assert report["execution_settings"]["build_cmd_release"]

    def test_release_crash_without_backtrace_remains_inconclusive(
            self, tmp_path, scenario_repo, local_transport, monkeypatch):
        monkeypatch.setattr(
            "runner.sandbox.DockerSandboxRunner._gdb_backtrace",
            lambda *args, **kwargs: "",
        )
        config = _config(
            tmp_path, scenario_repo, "correct",
            build_cmd_release="gcc -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O2 -o vuln vuln.c",
        )
        report = _run(tmp_path, config)
        assert report["exit_code"] == 40
        assert any(
            finding["build_type"] == "release"
            and finding["status"] == "Inconclusive"
            for finding in report["findings"]
        )
        assert any(
            finding["build_type"] == "sanitized"
            and finding["status"] == "Fixed"
            for finding in report["findings"]
        )

    def test_incomplete_scenario_remains_vulnerable(self, tmp_path, scenario_repo,
                                                    local_transport):
        report = _run(tmp_path, _config(tmp_path, scenario_repo, "incomplete"))
        assert report["exit_code"] == 10
        assert any(f["status"] == "Incomplete Fix" for f in report["findings"])
        assert any(f["status"] == "Fixed" for f in report["findings"])

    def test_regression_scenario_reports_functional_regression(
            self, tmp_path, scenario_repo, local_transport):
        report = _run(tmp_path, _config(tmp_path, scenario_repo, "regression"))
        assert report["exit_code"] == 20
        assert any(f["status"] == "Functional Regression"
                   for f in report["findings"])
        assert report["functional_tests_passed"] is False

    def test_no_bug_scenario_is_inconclusive(self, tmp_path, scenario_repo,
                                             local_transport):
        config = _config(tmp_path, scenario_repo, "correct")
        data = yaml.safe_load(config.read_text())
        data["base_ref"] = scenario_repo["correct"]
        config.write_text(yaml.safe_dump(data))
        report = _run(tmp_path, config)
        assert report["exit_code"] == 40
        assert report["base_bug_reproduced"] is False

    def test_build_failure_reports_30(self, tmp_path, scenario_repo,
                                      local_transport):
        config = _config(
            tmp_path, scenario_repo, "correct",
            build_cmd_release="gcc -O2 -o vuln missing_source.c",
        )
        report = _run(tmp_path, config)
        assert report["exit_code"] == 30
        assert report["errors"]
        assert report["mandatory_checks_complete"] is False

    @pytest.mark.parametrize("override,match", [
        ({"tests": []}, "nonempty list"),
        ({"tests": [{"id": "x", "kind": "functional", "input": "a",
                     "expected_exit_code": 0, "is_valid_input": True,
                     "stdout_kind": "exact", "stdout_value": "a\n"},
                    {"id": "x", "kind": "functional", "input": "b",
                     "expected_exit_code": 0, "is_valid_input": True,
                     "stdout_kind": "exact", "stdout_value": "b\n"}]},
         "duplicate test id"),
        ({"argv_template": ["{input}", "{input}"]}, "argv_template"),
        ({"work_dir": str(Path(scenario_repo["repo"]))} if False else
         {"work_dir": "__invalid__", "repo_path": "__none__"}, "repo_path"),
        ({"output_dir": "work/in/repo"}, "output_dir"),
    ])
    def test_invalid_configs_rejected_before_execution(
            self, tmp_path, scenario_repo, local_transport, override, match):

        if "repo_path" in override and override["repo_path"] == "__none__":
            override = dict(override)
            override["repo_path"] = str(tmp_path / "missing_repo")
            override.pop("work_dir")
        if override.get("output_dir") == "work/in/repo":
            override = dict(override)
            override["output_dir"] = str(Path(scenario_repo["repo"]) / "out")
        config = _config(tmp_path, scenario_repo, "correct", **override)
        report = _run(tmp_path, config)
        assert report["exit_code"] == 30
        assert any(match in error for error in report["errors"])
        assert report["executions"] == []

    def test_runtime_provenance_failure_keeps_partial_evidence(
            self, tmp_path, scenario_repo, local_transport, monkeypatch):
        config = _config(tmp_path, scenario_repo, "correct")

        original = __import__("runner.adapter", fromlist=["TargetRunnerAdapter"])
        original_run = original.TargetRunnerAdapter.run
        calls = {"n": 0}

        def flaky_run(self, input_bytes, *, version, build_type, timeout_sec):
            calls["n"] += 1
            if calls["n"] > 3:
                raise ValueError("execution context mismatch: injected")
            return original_run(self, input_bytes, version=version,
                                build_type=build_type, timeout_sec=timeout_sec)

        monkeypatch.setattr(original.TargetRunnerAdapter, "run", flaky_run)
        report = _run(tmp_path, config)
        assert report["exit_code"] == 30
        assert report["executions"]
        assert report["mandatory_checks_complete"] is False

    def test_failed_regression_verification_gates_pass(
            self, tmp_path, scenario_repo, local_transport):
        config = _config(tmp_path, scenario_repo, "correct")
        data = yaml.safe_load(config.read_text())
        for test in data["tests"]:
            if test["id"] == "poc-overflow":
                test["patched_expect"] = {"crash": False, "exit_code": 99}
        config.write_text(yaml.safe_dump(data))
        report = _run(tmp_path, config)
        assert report["exit_code"] == 40
        assert report["mandatory_checks_complete"] is False
        entries = report["regression_entries"]
        assert any(not entry["verified"] for entry in entries)
        assert any("reasons" in entry for entry in entries)

    def test_timeout_security_test_no_longer_vanishes(
            self, tmp_path, scenario_repo, local_transport, monkeypatch):
        import runner.sandbox as sandbox_mod

        real_run_raw = sandbox_mod.DockerSandboxRunner.run_raw

        def timeout_raw(self, artifact, config, input_bytes=None, args=None):
            result = real_run_raw(self, artifact, config, input_bytes, args)
            if input_bytes and b"TIMEOUTME" in input_bytes:
                result["timed_out"] = True
                result["exit_code"] = 124
            return result

        monkeypatch.setattr(sandbox_mod.DockerSandboxRunner, "run_raw",
                            timeout_raw)
        poc_timeout = {"id": "poc-timeout", "kind": "security",
                       "input": "TIMEOUTME", "expected_exit_code": None,
                       "is_valid_input": False, "stdout_kind": "none",
                       "base_expect": {"crash": True},
                       "patched_expect": {"crash": False, "exit_code": 1}}
        config = _config(tmp_path, scenario_repo, "correct")
        data = yaml.safe_load(config.read_text())
        data["tests"].append(poc_timeout)
        config.write_text(yaml.safe_dump(data))
        report = _run(tmp_path, config)
        assert report["exit_code"] == 40
        assert report["mandatory_checks_complete"] is False
        assert report["evidence_gaps"]
        assert any("poc-timeout" in f["finding_id"] for f in report["findings"])

    @pytest.mark.parametrize("override,match", [
        ({"tests": [{"id": "a b", "kind": "functional", "input": "hi",
                     "expected_exit_code": 0, "is_valid_input": True,
                     "stdout_kind": "exact", "stdout_value": "ok:hi\n"}]},
         "must match"),
        ({"tests": [{"id": "short-ok", "kind": "functional", "input": "hi",
                     "expected_exit_code": 0, "is_valid_input": True,
                     "stdout_kind": "regex", "stdout_value": "(["}]},
         "invalid stdout regex"),
        ({"tests": [{"id": "short-ok", "kind": "functional", "input": "hi",
                     "expected_exit_code": 0, "is_valid_input": True,
                     "stdout_kind": "exact", "stdout_value": "ok:hi\n",
                     "stderr_pattern": "(["}]},
         "invalid stderr_pattern regex"),
        ({"tests": [{"id": "short-ok", "kind": "functional", "input": "hi",
                     "expected_exit_code": None, "is_valid_input": True,
                     "stdout_kind": "exact", "stdout_value": "ok:hi\n"}]},
         "explicit integer expected_exit_code"),
        ({"timeout_sec": ".nan"}, "finite"),
        ({"timeout_sec": ".inf"}, "finite"),
        ({"cpus": "nan"}, "finite"),
    ])
    def test_invalid_configs_rejected_at_load(
            self, tmp_path, scenario_repo, local_transport, override, match):
        config = _config(tmp_path, scenario_repo, "correct", **override)
        report = _run(tmp_path, config)
        assert report["exit_code"] == 30
        assert any(match in error for error in report["errors"])
        assert report["executions"] == []

    def test_base_override_flag_is_honored(
            self, tmp_path, scenario_repo, local_transport):
        config = _config(tmp_path, scenario_repo, "correct")
        out_json = tmp_path / "report.json"
        out_md = tmp_path / "SUMMARY.md"
        report = run_validation(str(config), str(out_json), str(out_md),
                                base_override="NO-SUCH-REF")
        assert report["exit_code"] == 30
        assert any("Unknown git ref" in error for error in report["errors"])

    def test_saved_regressions_rerun_on_later_validation(
            self, tmp_path, scenario_repo, local_transport):
        config = _config(tmp_path, scenario_repo, "correct")
        first = _run(tmp_path, config)
        assert first["exit_code"] == 0
        assert all(entry["stage"] == "promoted"
                   for entry in first["regression_entries"])
        second = _run(tmp_path, config)
        assert second["exit_code"] == 0
        assert any(entry["stage"] == "saved"
                   for entry in second["regression_entries"])
        assert all(entry["verified"]
                   for entry in second["regression_entries"])

    def test_tampered_saved_regression_blocks_validation(
            self, tmp_path, scenario_repo, local_transport):
        config = _config(tmp_path, scenario_repo, "correct")
        first = _run(tmp_path, config)
        assert first["exit_code"] == 0
        suite = tmp_path / "out" / "regression_suite" / "auto_generated"
        saved_input = next(
            path for path in suite.iterdir()
            if path.is_file() and path.name.endswith(".bin")
        )
        saved_input.write_bytes(b"tampered")
        report = _run(tmp_path, config)
        assert report["exit_code"] == 30
        assert any("integrity check failed" in error
                   for error in report["errors"])

    def test_new_issue_promotes_patched_only_regression(
            self, tmp_path, scenario_repo, local_transport):
        config = _config(tmp_path, scenario_repo, "new_issue")
        data = yaml.safe_load(config.read_text())
        data["tests"].append({
            "id": "new-boom", "kind": "security", "input": "boom",
            "expected_exit_code": None, "is_valid_input": False,
            "stdout_kind": "none",
            "base_expect": {"crash": False, "exit_code": 0, "stdout_kind": "exact", "stdout_value": "ok:boom\n"},
            "patched_expect": {"crash": True},
        })
        config.write_text(yaml.safe_dump(data))
        report = _run(tmp_path, config)
        assert report["exit_code"] == 10
        assert any(f["status"] == "New Issue" and "new-boom" in f["finding_id"]
                   for f in report["findings"])
        assert any(entry["finding_id"].startswith("new-boom")
                   and entry["stage"] == "promoted" and entry["verified"]
                   for entry in report["regression_entries"])


@requires_docker
def test_cli_validate_end_to_end_with_real_docker(tmp_path):
    root = Path(__file__).resolve().parents[1]
    subprocess.run([str(root / "targets" / "build_fixture_target.sh")],
                   cwd=root, check=True, capture_output=True)
    env = dict(__import__("os").environ,
               PYTHONPATH=str(root / "src"))
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    result = subprocess.run(
        [sys.executable, "-m", "patch_validator",
         "validate", "--config", "targets/configs/scenario-correct.yaml",
         "--output-json", str(out_dir / "report.json"),
         "--output-md", str(out_dir / "SUMMARY.md")],
        cwd=root, env=env, capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    import json
    report = json.loads((out_dir / "report.json").read_text())
    assert report["exit_code"] == 0
    assert any(f["status"] == "Fixed" for f in report["findings"])
