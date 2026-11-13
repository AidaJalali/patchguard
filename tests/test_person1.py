"""Person 1 verification suite: config, build, sandbox, diagnostics."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from src.builder.builder import DualBuilder
from src.config.loader import load_target_config
from src.diagnostics.parser import DiagnosticsParser
from src.exceptions import ConfigOrBuildError
from src.models import BuildArtifact
from src.runner.sandbox import DockerSandboxRunner
from tests.conftest import IMAGE, make_config_dict, requires_docker


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def test_invalid_yaml_raises_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(":\n  - broken: [", encoding="utf-8")
    with pytest.raises(ConfigOrBuildError) as exc_info:
        load_target_config(str(bad))
    assert exc_info.value.code == 30


def test_missing_required_keys_raise(tmp_path: Path, vuln_repo: Path) -> None:
    cfg = tmp_path / "incomplete.yaml"
    cfg.write_text(
        yaml.dump({"target_name": "x", "repo_path": str(vuln_repo)}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigOrBuildError) as exc_info:
        load_target_config(str(cfg))
    assert exc_info.value.code == 30
    assert "Missing required" in exc_info.value.message


def test_invalid_input_mode_raises(tmp_path: Path, vuln_repo: Path) -> None:
    data = make_config_dict(vuln_repo, input_mode="socket")
    cfg = tmp_path / "bad_mode.yaml"
    cfg.write_text(yaml.dump(data), encoding="utf-8")
    with pytest.raises(ConfigOrBuildError) as exc_info:
        load_target_config(str(cfg))
    assert exc_info.value.code == 30


def test_timeout_and_memory_bounds(tmp_path: Path, vuln_repo: Path) -> None:
    for overrides in ({"timeout_sec": 0}, {"memory_mb": 32}):
        data = make_config_dict(vuln_repo, **overrides)
        cfg = tmp_path / "bounds.yaml"
        cfg.write_text(yaml.dump(data), encoding="utf-8")
        with pytest.raises(ConfigOrBuildError) as exc_info:
            load_target_config(str(cfg))
        assert exc_info.value.code == 30


def test_valid_config_loads(tmp_path: Path, vuln_repo: Path) -> None:
    data = make_config_dict(vuln_repo)
    cfg = tmp_path / "ok.yaml"
    cfg.write_text(yaml.dump(data), encoding="utf-8")
    loaded = load_target_config(str(cfg))
    assert loaded.target_name == "vuln"
    assert loaded.input_mode == "args"
    assert loaded.timeout_sec == 2.0


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigOrBuildError) as exc_info:
        load_target_config(str(tmp_path / "nope.yaml"))
    assert exc_info.value.code == 30


# ---------------------------------------------------------------------------
# Diagnostics parser (no Docker)
# ---------------------------------------------------------------------------


def _artifact(build_type: str = "sanitized") -> BuildArtifact:
    return BuildArtifact(
        version="base",
        build_type=build_type,  # type: ignore[arg-type]
        commit_hash="deadbeef",
        binary_path="/tmp/vuln",
        binary_sha256="0" * 64,
        compile_flags="-O1",
        build_dir="/tmp/build",
    )


def test_parser_asan_heap_buffer_overflow() -> None:
    stderr = textwrap.dedent(
        """
        ==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018
        #0 0x4c3f1a in main /src/vuln.c:20
        #1 0x7f000000 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29d90)
        """
    ).strip()
    parser = DiagnosticsParser()
    result = parser.parse(
        test_id="t_asan",
        artifact=_artifact("sanitized"),
        exit_code=1,
        stdout="",
        stderr=stderr,
        timed_out=False,
        oom_killed=False,
        duration_ms=12,
        cli_command="./vuln AAAA...",
    )
    assert result.crashed is True
    assert result.detection_mechanism == "ASAN"
    assert result.error_type == "heap-buffer-overflow"
    assert result.stack_trace
    assert result.stack_trace[0].function_name == "main"
    assert result.stack_trace[0].file_path == "/src/vuln.c"
    assert result.stack_trace[0].line_number == 20


def test_parser_asan_null_dereference() -> None:
    stderr = (
        "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000\n"
        "#0 0x4011aa in main /src/vuln.c:14\n"
    )
    result = DiagnosticsParser().parse(
        test_id="t_null",
        artifact=_artifact("sanitized"),
        exit_code=1,
        stdout="",
        stderr=stderr,
        timed_out=False,
        oom_killed=False,
        duration_ms=5,
        cli_command="./vuln segv",
    )
    assert result.crashed is True
    assert result.detection_mechanism == "ASAN"
    assert result.error_type == "null-dereference"


def test_parser_sigsegv_os_signal() -> None:
    result = DiagnosticsParser().parse(
        test_id="t_segv",
        artifact=_artifact("release"),
        exit_code=139,
        stdout="",
        stderr="Segmentation fault",
        timed_out=False,
        oom_killed=False,
        duration_ms=3,
        cli_command="./vuln segv",
    )
    assert result.crashed is True
    assert result.detection_mechanism == "OS_SIGNAL"
    assert result.signal == "SIGSEGV"
    assert result.error_type == "unclassified-crash"


def test_parser_timeout_not_crash() -> None:
    result = DiagnosticsParser().parse(
        test_id="t_timeout",
        artifact=_artifact("release"),
        exit_code=124,
        stdout="",
        stderr="",
        timed_out=True,
        oom_killed=False,
        duration_ms=2000,
        cli_command="./vuln hang",
    )
    assert result.timed_out is True
    assert result.crashed is False
    assert result.detection_mechanism == "TIMEOUT"
    assert result.error_type == "timeout"


def test_parser_oom_not_crash() -> None:
    result = DiagnosticsParser().parse(
        test_id="t_oom",
        artifact=_artifact("release"),
        exit_code=137,
        stdout="",
        stderr="",
        timed_out=False,
        oom_killed=True,
        duration_ms=100,
        cli_command="./vuln",
    )
    assert result.oom_killed is True
    assert result.crashed is False
    assert result.detection_mechanism == "OOM"
    assert result.error_type == "oom"


def test_parser_ubsan_divide_by_zero() -> None:
    stderr = "vuln.c:10:5: runtime error: division by zero\n"
    result = DiagnosticsParser().parse(
        test_id="t_ubsan",
        artifact=_artifact("sanitized"),
        exit_code=1,
        stdout="",
        stderr=stderr,
        timed_out=False,
        oom_killed=False,
        duration_ms=4,
        cli_command="./vuln",
    )
    assert result.crashed is True
    assert result.detection_mechanism == "UBSAN"
    assert result.error_type == "divide-by-zero"


def test_parser_stack_canary() -> None:
    stderr = "*** stack smashing detected ***: terminated\n"
    result = DiagnosticsParser().parse(
        test_id="t_canary",
        artifact=_artifact("release"),
        exit_code=134,
        stdout="",
        stderr=stderr,
        timed_out=False,
        oom_killed=False,
        duration_ms=4,
        cli_command="./vuln",
    )
    assert result.crashed is True
    assert result.detection_mechanism == "BINARY_PROTECTION"
    assert result.error_type == "stack-canary-abort"


# ---------------------------------------------------------------------------
# Integration: DualBuilder + DockerSandboxRunner
# ---------------------------------------------------------------------------


@requires_docker
def test_dual_builder_release_and_sanitized(tmp_path: Path, vuln_repo: Path) -> None:
    data = make_config_dict(vuln_repo)
    cfg_path = tmp_path / "target_config.yaml"
    cfg_path.write_text(yaml.dump(data), encoding="utf-8")
    config = load_target_config(str(cfg_path))

    work = tmp_path / "work"
    builder = DualBuilder(image=IMAGE)
    artifacts = builder.build_all(config, str(work))

    assert ("base", "release") in artifacts
    assert ("base", "sanitized") in artifacts
    assert ("patched", "release") in artifacts
    assert ("patched", "sanitized") in artifacts

    base_rel = artifacts[("base", "release")]
    base_san = artifacts[("base", "sanitized")]
    assert Path(base_rel.binary_path).is_file()
    assert Path(base_san.binary_path).is_file()
    assert base_rel.binary_sha256 != base_san.binary_sha256
    assert base_rel.build_dir != base_san.build_dir
    assert "-fsanitize" in base_san.compile_flags
    assert "-O2" in base_rel.compile_flags


@requires_docker
def test_asan_heap_overflow_and_sigsegv_live(tmp_path: Path, vuln_repo: Path) -> None:
    data = make_config_dict(vuln_repo)
    cfg_path = tmp_path / "target_config.yaml"
    cfg_path.write_text(yaml.dump(data), encoding="utf-8")
    config = load_target_config(str(cfg_path))

    artifacts = DualBuilder(image=IMAGE).build_all(config, str(tmp_path / "work"))
    runner = DockerSandboxRunner(image=IMAGE, enable_gdb_on_release_crash=False)

    # Sanitized base: long payload -> ASan heap-buffer-overflow
    san = artifacts[("base", "sanitized")]
    overflow = runner.run(
        san,
        config,
        test_id="overflow",
        args=["AAAAAAAAAAAA"],  # > 8 bytes
    )
    assert overflow.crashed is True
    assert overflow.detection_mechanism == "ASAN"
    assert overflow.error_type == "heap-buffer-overflow"
    assert overflow.stack_trace  # frames populated

    # Release base: segv mode -> SIGSEGV / OS_SIGNAL
    rel = artifacts[("base", "release")]
    segv = runner.run(rel, config, test_id="segv", args=["segv"])
    assert segv.crashed is True
    assert segv.signal == "SIGSEGV"
    assert segv.detection_mechanism in ("OS_SIGNAL", "ASAN")
    assert segv.error_type in ("unclassified-crash", "null-dereference")


@requires_docker
def test_timeout_sets_flag_without_crash(tmp_path: Path, vuln_repo: Path) -> None:
    data = make_config_dict(vuln_repo, timeout_sec=1.0)
    cfg_path = tmp_path / "target_config.yaml"
    cfg_path.write_text(yaml.dump(data), encoding="utf-8")
    config = load_target_config(str(cfg_path))

    artifacts = DualBuilder(image=IMAGE).build_all(config, str(tmp_path / "work"))
    runner = DockerSandboxRunner(image=IMAGE, enable_gdb_on_release_crash=False)
    result = runner.run(
        artifacts[("base", "release")],
        config,
        test_id="hang",
        args=["hang"],
    )
    assert result.timed_out is True
    assert result.crashed is False
    assert result.detection_mechanism == "TIMEOUT"
    assert result.error_type == "timeout"


@requires_docker
def test_patched_sanitized_rejects_overflow(tmp_path: Path, vuln_repo: Path) -> None:
    data = make_config_dict(vuln_repo)
    cfg_path = tmp_path / "target_config.yaml"
    cfg_path.write_text(yaml.dump(data), encoding="utf-8")
    config = load_target_config(str(cfg_path))
    artifacts = DualBuilder(image=IMAGE).build_all(config, str(tmp_path / "work"))
    runner = DockerSandboxRunner(image=IMAGE, enable_gdb_on_release_crash=False)

    result = runner.run(
        artifacts[("patched", "sanitized")],
        config,
        test_id="patched_overflow",
        args=["AAAAAAAAAAAA"],
    )
    assert result.crashed is False
    assert result.detection_mechanism == "NONE"
    assert result.exit_code == 1  # graceful rejection
