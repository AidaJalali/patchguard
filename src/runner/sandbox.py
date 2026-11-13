from __future__ import annotations

import re
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Tuple

from diagnostics.parser import DiagnosticsParser
from models import BuildArtifact, ExecutionResult, TargetConfig

DEFAULT_IMAGE = "patchguard-sandbox:latest"


def input_to_args(input_bytes: bytes) -> list[str]:
    if b"\0" in input_bytes:
        raise ValueError("argv input cannot contain null bytes")
    text = input_bytes.decode("utf-8", errors="surrogateescape").strip(" \t\n")
    return re.split(r"[ \t\n]+", text) if text else []


class DockerSandboxRunner:
    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        docker_bin: str = "docker",
        parser: Optional[DiagnosticsParser] = None,
        enable_gdb_on_release_crash: bool = True,
    ) -> None:
        self.image = image
        self.docker_bin = docker_bin
        self.parser = parser or DiagnosticsParser()
        self.enable_gdb_on_release_crash = enable_gdb_on_release_crash

    def run(
        self,
        artifact: BuildArtifact,
        config: TargetConfig,
        test_id: str,
        input_bytes: Optional[bytes] = None,
        args: Optional[List[str]] = None,
    ) -> ExecutionResult:
        raw = self.run_raw(artifact, config, input_bytes=input_bytes, args=args)

        gdb_bt = ""
        if (
            self.enable_gdb_on_release_crash
            and artifact.build_type == "release"
            and not raw["timed_out"]
            and not raw["oom_killed"]
            and self._looks_like_crash(raw["exit_code"], raw["stderr"])
        ):
            gdb_bt = self._gdb_backtrace(artifact, config, input_bytes, args)

        return self.parser.parse(
            test_id=test_id,
            artifact=artifact,
            exit_code=raw["exit_code"],
            stdout=raw["stdout"],
            stderr=raw["stderr"],
            timed_out=raw["timed_out"],
            oom_killed=raw["oom_killed"],
            duration_ms=raw["duration_ms"],
            cli_command=raw["cli_command"],
            gdb_backtrace=gdb_bt,
        )

    def run_raw(
        self,
        artifact: BuildArtifact,
        config: TargetConfig,
        input_bytes: Optional[bytes] = None,
        args: Optional[List[str]] = None,
    ) -> dict:

        binary = Path(artifact.binary_path).resolve()
        if not binary.is_file():
            raise FileNotFoundError(f"Binary not found: {binary}")

        with tempfile.TemporaryDirectory(prefix="patchguard_run_") as tmp:
            tmp_path = Path(tmp)
            input_file = tmp_path / "input.bin"
            if input_bytes is not None:
                input_file.write_bytes(input_bytes)
            else:
                input_file.write_bytes(b"")

            argv = self._build_argv(config, args, input_bytes)
            container_cmd, cli_command = self._compose_container_command(
                config=config,
                argv=argv,
                has_stdin=(config.input_mode == "stdin"),
            )

            docker_cmd = self._docker_run_argv(
                config=config,
                binary=binary,
                work_dir=tmp_path,
                container_cmd=container_cmd,
            )

            return self._execute(
                docker_cmd=docker_cmd,
                cli_command=cli_command,
                stdin_bytes=input_bytes if config.input_mode == "stdin" else None,
                timeout_sec=config.timeout_sec,
            )

    def _build_argv(
        self,
        config: TargetConfig,
        args: Optional[List[str]],
        input_bytes: Optional[bytes],
    ) -> List[str]:
        if config.input_mode == "stdin":
            return list(args or [])

        if config.input_mode == "file":
            argv = list(args) if args is not None else []
            if argv:
                argv = [a.replace("{input_file}", "/work/input.bin") for a in argv]
                if not any("/work/input.bin" in a for a in argv):
                    argv.append("/work/input.bin")
            else:
                argv = ["/work/input.bin"]
            return argv

        if args is not None:
            return list(args)
        if input_bytes is not None:
            return input_to_args(input_bytes)
        return []

    def _compose_container_command(
        self,
        config: TargetConfig,
        argv: List[str],
        has_stdin: bool,
    ) -> Tuple[str, str]:
        bin_path = "/artifact/binary"
        quoted_args = " ".join(shlex.quote(a) for a in argv)
        cmd = f"{bin_path} {quoted_args}".strip()

        env_prefix = " ".join(
            f"export {shlex.quote(k)}={shlex.quote(v)};"
            for k, v in config.env_vars.items()
        )
        if env_prefix:
            full = f"{env_prefix} {cmd}"
        else:
            full = cmd
        return full, full

    def _docker_run_argv(
        self,
        config: TargetConfig,
        binary: Path,
        work_dir: Path,
        container_cmd: str,
    ) -> List[str]:
        bin_dir = self._docker_path(str(binary.parent))
        bin_name = binary.name
        work = self._docker_path(str(work_dir.resolve()))

        cmd = [
            self.docker_bin,
            "run",
            "--rm",
            "--network",
            "none",
            f"--memory={config.memory_mb}m",
            f"--cpus={config.cpus}",
            "--pids-limit",
            "64",
            "--user",
            "1000:1000",
            "-v",
            f"{bin_dir}:/artifact:ro",
            "-v",
            f"{work}:/work",
            "-w",
            "/work",
        ]
        if config.input_mode == "stdin":
            cmd.append("-i")
        cmd.extend(
            [
                "--entrypoint",
                "bash",
                self.image,
                "-lc",
                (
                    f"cp /artifact/{shlex.quote(bin_name)} /tmp/binary && chmod +x /tmp/binary; "
                    + container_cmd.replace("/artifact/binary", "/tmp/binary")
                ),
            ]
        )
        return cmd

    def _execute(
        self,
        docker_cmd: List[str],
        cli_command: str,
        stdin_bytes: Optional[bytes],
        timeout_sec: float,
    ) -> dict:
        container_name = f"patchguard_{os_getpid()}_{int(time.time() * 1000)}"

        named_cmd = list(docker_cmd)

        try:
            run_idx = named_cmd.index("run")
            named_cmd.insert(run_idx + 1, container_name)
            named_cmd.insert(run_idx + 1, "--name")
        except ValueError:
            pass

        started = time.monotonic()
        timed_out = False
        oom_killed = False
        exit_code = -1
        stdout = ""
        stderr = ""

        try:
            proc = subprocess.run(
                named_cmd,
                input=stdin_bytes,
                capture_output=True,
                timeout=timeout_sec,
            )
            exit_code = proc.returncode
            stdout = (
                proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
            )
            stderr = (
                proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            )
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            self._docker_kill(container_name)
            exit_code = 124
        except FileNotFoundError:
            raise

        duration_ms = int((time.monotonic() - started) * 1000)

        oom_killed = self._check_oom(container_name, exit_code)
        if exit_code == 137:
            oom_killed = True

        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "oom_killed": oom_killed,
            "duration_ms": duration_ms,
            "cli_command": cli_command,
        }

    def _docker_kill(self, name: str) -> None:
        subprocess.run(
            [self.docker_bin, "kill", name],
            capture_output=True,
            timeout=30,
        )

    def _check_oom(self, name: str, exit_code: int) -> bool:
        if exit_code == 137:
            return True
        try:
            result = subprocess.run(
                [
                    self.docker_bin,
                    "inspect",
                    "--format",
                    "{{.State.OOMKilled}}",
                    name,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip().lower() == "true"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def _looks_like_crash(self, exit_code: int, stderr: str) -> bool:
        if exit_code < 0 or exit_code >= 128:
            return True
        markers = ("Segmentation fault", "Aborted", "stack smashing", "core dumped")
        return any(m.lower() in stderr.lower() for m in markers)

    def _gdb_backtrace(
        self,
        artifact: BuildArtifact,
        config: TargetConfig,
        input_bytes: Optional[bytes],
        args: Optional[List[str]],
    ) -> str:

        binary = Path(artifact.binary_path).resolve()
        argv = self._build_argv(config, args, input_bytes)
        quoted = " ".join(shlex.quote(a) for a in argv)
        run_args = quoted

        with tempfile.TemporaryDirectory(prefix="patchguard_gdb_") as tmp:
            tmp_path = Path(tmp)
            if input_bytes is not None:
                (tmp_path / "input.bin").write_bytes(input_bytes)

            bin_dir = self._docker_path(str(binary.parent))
            work = self._docker_path(str(tmp_path.resolve()))
            bin_name = binary.name

            if config.input_mode == "stdin":
                gdb_script = (
                    f"cp /artifact/{shlex.quote(bin_name)} /tmp/binary && chmod +x /tmp/binary; "
                    f"gdb -batch -ex 'set pagination off' "
                    f"-ex 'run {run_args} < /work/input.bin' "
                    f"-ex 'bt' --args /tmp/binary"
                )
            else:
                gdb_script = (
                    f"cp /artifact/{shlex.quote(bin_name)} /tmp/binary && chmod +x /tmp/binary; "
                    f"gdb -batch -ex 'set pagination off' "
                    f"-ex 'run {run_args}' "
                    f"-ex 'bt' --args /tmp/binary {run_args}"
                )

            cmd = [
                self.docker_bin,
                "run",
                "--rm",
                "--network",
                "none",
                f"--memory={config.memory_mb}m",
                f"--cpus={config.cpus}",
                "--pids-limit",
                "64",
                "--user",
                "1000:1000",
                "-v",
                f"{bin_dir}:/artifact:ro",
                "-v",
                f"{work}:/work",
                "-w",
                "/work",
                self.image,
                "bash",
                "-lc",
                gdb_script,
            ]
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=max(config.timeout_sec * 2, 10),
                )
                out = result.stdout.decode("utf-8", errors="replace")
                err = result.stderr.decode("utf-8", errors="replace")
                return out + "\n" + err
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                return ""

    @staticmethod
    def _docker_path(host_path: str) -> str:
        return host_path.replace("\\", "/")


def os_getpid() -> int:
    import os

    return os.getpid()
