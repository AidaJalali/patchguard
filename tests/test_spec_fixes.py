from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from builder.builder import DualBuilder
from config.loader import load_validation_config
from diagnostics.parser import DiagnosticsParser
from exceptions import ConfigOrBuildError
from helpers import make_clean, make_crash
from models import BuildArtifact, crash_signature
from regression_gen.generator import RegressionError, RegressionExpectation, VersionExpectation, verify_regression
from reproducer.bundler import MinimizationResult, create_bundle
from runner.sandbox import DockerSandboxRunner
from test_bundler import make_finding, make_replay
from test_regression_gen import VersionedRunner
from test_validation import _config, _git, _run, local_transport, scenario_repo
from conftest import requires_docker, IMAGE


@pytest.mark.parametrize("name", ["src_base", "src_patched", "build_base_release", "build_patched_sanitized"])
def test_checkout_cannot_delete_source_repository(tmp_path, scenario_repo, name):
    repo = tmp_path / "workspace" / name
    repo.parent.mkdir()
    shutil.copytree(scenario_repo["repo"], repo)
    config_path = _config(tmp_path, {**scenario_repo, "repo": str(repo)}, "correct")
    data = yaml.safe_load(config_path.read_text())
    data["work_dir"] = str(repo.parent)
    config_path.write_text(yaml.safe_dump(data))
    original = (repo / "vuln.c").read_bytes()
    with pytest.raises(ConfigOrBuildError, match="overlap"):
        load_validation_config(str(config_path))
    safe_path = _config(tmp_path, scenario_repo, "correct")
    cfg = load_validation_config(str(safe_path))
    target = replace(cfg.target, repo_path=str(repo))
    with pytest.raises(ConfigOrBuildError, match="overlap"):
        DualBuilder().build_all(target, str(repo.parent))
    with pytest.raises(ConfigOrBuildError, match="overlap"):
        DualBuilder()._prepare_checkouts(target, repo.parent)
    assert (repo / "vuln.c").read_bytes() == original
    assert (repo / ".git").is_dir()


@pytest.mark.parametrize("category", ["functional", "boundary", "security"])
def test_missing_category_rejected_before_build(tmp_path, scenario_repo, monkeypatch, category):
    path = _config(tmp_path, scenario_repo, "correct")
    data = yaml.safe_load(path.read_text())
    data["tests"] = [test for test in data["tests"] if test["kind"] != category]
    path.write_text(yaml.safe_dump(data))
    monkeypatch.setattr(DualBuilder, "build_all", lambda *a: pytest.fail("invalid suite reached builder"))
    report = _run(tmp_path, path)
    assert report["exit_code"] == 30
    assert not report["mandatory_checks_complete"]


@pytest.mark.parametrize("stdout,stderr", [("wrong", "expected error"), ("ok", "wrong error")])
def test_generated_regression_rejects_wrong_output(stdout, stderr):
    crash = make_crash()
    expectation = RegressionExpectation(
        VersionExpectation(True, signature=crash_signature(crash), test_id="t1"),
        VersionExpectation(False, exit_code=1, test_id="t1", stdout_kind="exact", stdout_value="ok", stderr_pattern="expected error"),
    )
    runner = VersionedRunner(base=crash, patched=make_clean(version="patched", exit_code=1, stdout=stdout, stderr=stderr))
    result = verify_regression(runner, b"input", expectation, build_type="sanitized")
    assert result.base.ok
    assert not result.patched.ok


def test_missing_regression_oracle_refused_before_execution():
    expectation = RegressionExpectation(
        VersionExpectation(True, signature=crash_signature(make_crash()), test_id="t1"),
        VersionExpectation(False, exit_code=0, test_id="t1"),
    )
    runner = VersionedRunner(base=make_crash(), patched=make_clean(version="patched"))
    with pytest.raises(RegressionError, match="independent stdout oracle"):
        verify_regression(runner, b"input", expectation, build_type="sanitized")
    assert not runner.calls


def test_configured_defines_reach_ast(tmp_path, scenario_repo, local_transport):
    repo = Path(scenario_repo["repo"])
    for key in ("base", "correct"):
        _git(repo, "checkout", "--detach", scenario_repo[key])
        source = repo / "vuln.c"
        include = repo / "include"
        include.mkdir(exist_ok=True)
        (include / "review.h").write_text('#ifndef REVIEW_FLAG\n#error missing configured flag\n#endif\n')
        source.write_text('#include <review.h>\n' + source.read_text())
        _git(repo, "add", "vuln.c", "include/review.h")
        _git(repo, "commit", "-qm", "Require configured macro")
        scenario_repo[key] = _git(repo, "rev-parse", "HEAD")
    path = _config(tmp_path, scenario_repo, "correct", analysis_args=["-DREVIEW_FLAG=1", "-Iinclude"])
    data = yaml.safe_load(path.read_text())
    for key in ("build_cmd_release", "build_cmd_sanitized"):
        data[key] = data[key].replace("gcc ", "gcc -DREVIEW_FLAG=1 -Iinclude ", 1)
    path.write_text(yaml.safe_dump(data))
    assert _run(tmp_path, path)["exit_code"] == 0


def test_crash_pipeline_forwards_timeout(tmp_path, scenario_repo, monkeypatch):
    import validation
    cfg = load_validation_config(str(_config(tmp_path, scenario_repo, "correct", timeout_sec=0.25)))
    calls = []
    monkeypatch.setattr(validation, "verify_reproducibility", lambda *a, **kw: calls.append(kw))
    monkeypatch.setattr(validation, "build_reproducer", lambda *a, **kw: calls.append(kw))
    artifact = BuildArtifact("base", "sanitized", "hash", "/tmp/binary", "hash", "flags", "/tmp")
    validation._crash_evidence("finding", cfg.tests[-1], make_crash(), "sanitized", cfg,
        type("Adapter", (), {"argv_template": ["{input}"]})(),
        {("base", "sanitized"): artifact, ("patched", "sanitized"): artifact}, output_root=tmp_path)
    assert [call["timeout_sec"] for call in calls] == [0.25, 0.25]


def fake_docker(tmp_path, state):
    path = tmp_path / "docker"
    path.write_text(f"#!{sys.executable}\nimport json,sys\n"
        "if sys.argv[1] == 'run':\n print('target output'); sys.exit(125)\n"
        f"if sys.argv[1] == 'inspect':\n state={state!r}\n"
        " if state is None: print('Cannot connect to Docker daemon',file=sys.stderr); sys.exit(125)\n"
        " print(json.dumps(state))\n")
    path.chmod(0o755)
    return path


def test_docker_launch_failure_is_infrastructure_error(tmp_path):
    runner = DockerSandboxRunner(docker_bin=str(fake_docker(tmp_path, None)))
    with pytest.raises(ConfigOrBuildError, match="Docker launch"):
        runner._execute([str(tmp_path / "docker"), "run", "image"], "target", None, 2)


def test_target_exit_125_is_not_docker_failure(tmp_path):
    state = dict(Status="exited", StartedAt="2026-11-14T00:00:00Z", ExitCode=125, OOMKilled=False, Error="")
    runner = DockerSandboxRunner(docker_bin=str(fake_docker(tmp_path, state)))
    result = runner._execute([str(tmp_path / "docker"), "run", "image"], "target", None, 2)
    assert result["exit_code"] == 125
    assert result["stdout"] == "target output\n"


def test_canary_keeps_collected_gdb_frames():
    artifact = BuildArtifact("base", "release", "hash", "/tmp/a", "hash", "-O2", "/tmp")
    result = DiagnosticsParser().parse("test", artifact, 134, "", "*** stack smashing detected ***: terminated",
        False, False, 0, "target", gdb_backtrace="#0  main () at vuln.c:10\n")
    assert result.detection_mechanism == "BINARY_PROTECTION"
    assert result.stack_trace[0].function == "main"


@pytest.mark.parametrize("address,expected", [("0x00000000", "null-dereference"), ("0x41414141", "segv"), ("0x000041414141", "segv")])
def test_asan_segv_category_matches_address(address, expected):
    artifact = BuildArtifact("base", "sanitized", "hash", "/tmp/a", "hash", "flags", "/tmp")
    result = DiagnosticsParser().parse("test", artifact, 139, "",
        f"==1==ERROR: AddressSanitizer: SEGV on unknown address {address}\n#0 0x1234 in main /build/a.c:10\n",
        False, False, 0, "target")
    assert result.error_type == expected


def test_isolated_reproducer_records_and_uses_context(tmp_path):
    finding = make_finding(tmp_path, binary_path=Path("/bin/true"), sandbox_image="sha256:recorded",
        env_vars={"TAG": "with spaces"}, configured_env={"TAG": "with spaces"}, timeout_sec=2.5, memory_mb=128, cpus=0.5,
        build_command="gcc -DTEST=1 -fsanitize=address target.c", input_mode="args", argv_template=["{input}"])
    bundle = create_bundle(finding, replay=make_replay(3), minimized=MinimizationResult(b"A", revalidated=True), output_root=tmp_path / "out")
    root = Path(bundle.bundle_dir)
    bin_dir = tmp_path / "tools"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(f"#!{sys.executable}\nimport json,sys\nif sys.argv[1]=='run': print(json.dumps(sys.argv[1:]))\n")
    docker.chmod(0o755)
    result = subprocess.run(["sh", str(root / "reproduce.sh"), "minimized"], cwd="/tmp", capture_output=True, text=True,
        env={**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"]})
    assert result.returncode == 0, result.stderr
    args = json.loads(result.stdout)
    assert "sha256:recorded" in args
    assert "--memory=128m" in args and "--cpus=0.5" in args
    assert any("TAG=with spaces" in arg for arg in args)
    assert args[-1] == "A"
    metadata = json.loads((root / "metadata.json").read_text())
    assert metadata["execution"]["timeout_sec"] == 2.5
    assert metadata["build"]["command"] == finding.build_command


def test_saved_suite_survives_fresh_workspace(tmp_path, scenario_repo, local_transport):
    first = tmp_path / "first"
    first.mkdir()
    config = _config(first, scenario_repo, "correct")
    assert _run(first, config)["exit_code"] == 0
    second = tmp_path / "second"
    second.mkdir()
    suite = second / "restored-suite"
    shutil.copytree(first / "out" / "regression_suite", suite)
    config = _config(second, scenario_repo, "correct", regression_suite_dir=str(suite))
    shutil.rmtree(first)
    report = _run(second, config)
    assert report["exit_code"] == 0
    assert any(entry["stage"] == "saved" and entry["verified"] for entry in report["regression_entries"])


@pytest.mark.parametrize("limit,expected", [(7, 0), (5, 20)])
def test_unseen_commit_evaluated_from_code(tmp_path, scenario_repo, local_transport, limit, expected):
    repo = Path(scenario_repo["repo"])
    _git(repo, "checkout", "--detach", scenario_repo["correct"])
    source = repo / "vuln.c"
    operator = ">" if limit == 7 else ">="
    source.write_text(source.read_text().replace("strlen(argv[1]) >= 8", f"strlen(argv[1]) {operator} {limit}") + "\n")
    _git(repo, "add", "vuln.c")
    _git(repo, "commit", "-qm", "Held-out patch")
    scenario_repo["held-out"] = _git(repo, "rev-parse", "HEAD")
    assert _run(tmp_path, _config(tmp_path, scenario_repo, "held-out"))["exit_code"] == expected


@requires_docker
@pytest.mark.parametrize("mode", ["stdin", "file", "args"])
def test_container_replayer_modes_from_relocated_bundle(tmp_path, mode):
    image = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], text=True).strip()
    binary = tmp_path / "replay-target"
    binary.write_text('#!/usr/bin/python3\nimport os,sys\n'
        'data=sys.stdin.buffer.read() if len(sys.argv)==1 else '
        '(open(sys.argv[1],"rb").read() if sys.argv[1].startswith("/bundle/") else sys.argv[1].encode())\n'
        'print(os.environ["REPLAY_TEST"]+":"+data.decode())\n')
    binary.chmod(0o755)
    finding = make_finding(tmp_path, binary_path=binary, sandbox_image=image,
        input_bytes=b"PWN", input_mode=mode, argv_template=[] if mode == "stdin" else ["{input}"],
        env_vars={"REPLAY_TEST": "recorded"}, configured_env={"REPLAY_TEST": "recorded"})
    bundle = create_bundle(finding, replay=make_replay(3), minimized=MinimizationResult(b"PWN", revalidated=True), output_root=tmp_path / "out")
    relocated = tmp_path / "relocated"
    shutil.move(bundle.bundle_dir, relocated)
    binary.unlink()
    proc = subprocess.run(["sh", str(relocated / "reproduce.sh"), "minimized"], cwd="/tmp", capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "recorded:PWN\n"
