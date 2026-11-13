from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

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
                         ("regression", REGRESSION_C)):
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


def _local_run_raw(self, artifact, config, input_bytes=None, args=None):
    result = subprocess.run(
        [artifact.binary_path, *args],
        capture_output=True,
        timeout=config.timeout_sec,
        env={
            "ASAN_OPTIONS": "detect_leaks=0:symbolize=1",
            "ASAN_SYMBOLIZER_PATH": "/usr/bin/llvm-symbolizer-18",
            "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
        },
    )
    return dict(
        exit_code=result.returncode,
        stdout=result.stdout.decode(),
        stderr=result.stderr.decode(),
        timed_out=False,
        oom_killed=False,
        duration_ms=0,
        cli_command=artifact.binary_path,
    )


def _run(tmp_path: Path, config: Path) -> dict:
    out_json = tmp_path / "report.json"
    out_md = tmp_path / "SUMMARY.md"
    report = run_validation(str(config), str(out_json), str(out_md))
    assert out_json.is_file() and out_md.is_file()
    return report


class TestValidatePipeline:
    def test_correct_scenario_passes(self, tmp_path, scenario_repo, local_transport):
        report = _run(tmp_path, _config(tmp_path, scenario_repo, "correct"))
        assert report["exit_code"] == 0
        assert all(report[k] for k in (
            "base_bug_reproduced", "patch_fix_verified",
            "functional_tests_passed", "mandatory_checks_complete"))
        assert any(f["status"] == "Fixed" for f in report["findings"])
        assert report["reproducers"]
        assert all(entry["verified"] for entry in report["regression_entries"])

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
        [root / ".venv" / "bin" / "python", "-m", "patch_validator",
         "validate", "--config", "targets/configs/scenario-correct.yaml",
         "--base", "x", "--patched", "y",
         "--output-json", str(out_dir / "report.json"),
         "--output-md", str(out_dir / "SUMMARY.md")],
        cwd=root, env=env, capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    import json
    report = json.loads((out_dir / "report.json").read_text())
    assert report["exit_code"] == 0
    assert any(f["status"] == "Fixed" for f in report["findings"])
