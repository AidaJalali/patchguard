from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Dict, List, Tuple

from exceptions import ConfigOrBuildError
from models import BuildArtifact, BuildType, TargetConfig, VersionType

SANITIZED_FLAGS = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
RELEASE_FLAGS = "-O2"

DEFAULT_IMAGE = "patchguard-sandbox:latest"


_BUILD_MATRIX: List[Tuple[VersionType, BuildType, str, str, str]] = [
    ("base", "release", "src_base", "build_base_release", RELEASE_FLAGS),
    ("base", "sanitized", "src_base", "build_base_sanitized", SANITIZED_FLAGS),
    ("patched", "release", "src_patched", "build_patched_release", RELEASE_FLAGS),
    ("patched", "sanitized", "src_patched", "build_patched_sanitized", SANITIZED_FLAGS),
]


class DualBuilder:
    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        docker_bin: str = "docker",
    ) -> None:
        self.image = image
        self.docker_bin = docker_bin

    def build_all(
        self,
        config: TargetConfig,
        work_dir: str,
    ) -> Dict[Tuple[VersionType, BuildType], BuildArtifact]:
        work = Path(work_dir).resolve()
        work.mkdir(parents=True, exist_ok=True)

        commit_hashes = self._prepare_checkouts(config, work)
        artifacts: Dict[Tuple[VersionType, BuildType], BuildArtifact] = {}

        for version, build_type, src_name, build_name, flags in _BUILD_MATRIX:
            build_dir = work / build_name
            src_dir = work / src_name
            artifact = self._build_one(
                config=config,
                version=version,
                build_type=build_type,
                src_dir=src_dir,
                build_dir=build_dir,
                compile_flags=flags,
                commit_hash=commit_hashes[version],
            )
            artifacts[(version, build_type)] = artifact

        return artifacts

    def _prepare_checkouts(
        self,
        config: TargetConfig,
        work: Path,
    ) -> Dict[VersionType, str]:
        repo = Path(config.repo_path).resolve()
        if not repo.is_dir():
            raise ConfigOrBuildError(
                code=30,
                message=f"repo_path does not exist: {repo}",
            )

        hashes: Dict[VersionType, str] = {}
        for version, ref, dest_name in (
            ("base", config.base_ref, "src_base"),
            ("patched", config.patched_ref, "src_patched"),
        ):
            dest = work / dest_name
            if dest.exists():
                shutil.rmtree(dest)
            try:
                hashes[version] = self._extract_ref(repo, ref, dest)
            except ConfigOrBuildError:
                raise
            except Exception as exc:
                raise ConfigOrBuildError(
                    code=30,
                    message=f"Failed to extract {version} ref '{ref}': {exc}",
                ) from exc
        return hashes

    def _extract_ref(self, repo: Path, ref: str, dest: Path) -> str:

        dest.mkdir(parents=True, exist_ok=False)

        if (repo / ".git").exists() or (repo / ".git").is_file():
            return self._extract_git_ref(repo, ref, dest)

        shutil.copytree(repo, dest, dirs_exist_ok=True)
        return ref

    def _extract_git_ref(self, repo: Path, ref: str, dest: Path) -> str:

        try:
            commit = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--verify", ref],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except subprocess.CalledProcessError as exc:
            raise ConfigOrBuildError(
                code=30,
                message=f"Unknown git ref '{ref}': {exc.stderr}",
            ) from exc

        try:
            archive = subprocess.Popen(
                ["git", "-C", str(repo), "archive", commit],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            extract = subprocess.run(
                ["tar", "-x", "-C", str(dest)],
                stdin=archive.stdout,
                capture_output=True,
            )
            if archive.stdout:
                archive.stdout.close()
            archive.wait()
            if archive.returncode != 0 or extract.returncode != 0:
                raise RuntimeError("git archive extraction failed")
        except (FileNotFoundError, RuntimeError):
            if dest.exists():
                shutil.rmtree(dest)
            try:
                subprocess.run(
                    ["git", "clone", "--no-checkout", str(repo), str(dest)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                subprocess.run(
                    ["git", "-C", str(dest), "checkout", "--force", commit],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as exc:
                raise ConfigOrBuildError(
                    code=30,
                    message=f"git checkout failed for '{ref}': {exc.stderr}",
                ) from exc

        git_dir = dest / ".git"
        if git_dir.exists():
            try:
                commit = subprocess.run(
                    ["git", "-C", str(dest), "rev-parse", "HEAD"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
            except subprocess.CalledProcessError:
                pass
        return commit

    def _build_one(
        self,
        config: TargetConfig,
        version: VersionType,
        build_type: BuildType,
        src_dir: Path,
        build_dir: Path,
        compile_flags: str,
        commit_hash: str,
    ) -> BuildArtifact:
        if build_dir.exists():
            shutil.rmtree(build_dir)

        shutil.copytree(src_dir, build_dir, ignore=shutil.ignore_patterns(".git"))

        build_cmd = (
            config.build_cmd_sanitized
            if build_type == "sanitized"
            else config.build_cmd_release
        )

        env_exports = " ".join(
            f"export {self._shell_quote(k)}={self._shell_quote(v)};"
            for k, v in config.env_vars.items()
        )

        if build_type == "sanitized":
            flag_exports = (
                f"export CFLAGS={self._shell_quote(SANITIZED_FLAGS)}; "
                f"export CXXFLAGS={self._shell_quote(SANITIZED_FLAGS)}; "
                f"export LDFLAGS={self._shell_quote('-fsanitize=address,undefined')}; "
            )
        else:
            flag_exports = (
                f"export CFLAGS={self._shell_quote(RELEASE_FLAGS)}; "
                f"export CXXFLAGS={self._shell_quote(RELEASE_FLAGS)}; "
            )

        inner = f"{env_exports} {flag_exports} {build_cmd}"
        self._docker_build(build_dir, inner)

        binary_path = (build_dir / config.binary_rel_path).resolve()
        if not binary_path.is_file():
            raise ConfigOrBuildError(
                code=30,
                message=(
                    f"Binary not found after {version}/{build_type} build: "
                    f"{binary_path}"
                ),
            )

        self._verify_elf_x86_64(binary_path)
        digest = self._sha256(binary_path)

        return BuildArtifact(
            version=version,
            build_type=build_type,
            commit_hash=commit_hash,
            binary_path=str(binary_path),
            binary_sha256=digest,
            compile_flags=compile_flags,
            build_dir=str(build_dir.resolve()),
        )

    def _docker_build(self, build_dir: Path, shell_cmd: str) -> None:

        host_build = str(build_dir.resolve())

        mount_src = self._docker_path(host_build)

        cmd = [
            self.docker_bin,
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "0:0",
            "-v",
            f"{mount_src}:/build",
            "-w",
            "/build",
            self.image,
            "bash",
            "-lc",
            shell_cmd,
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError as exc:
            raise ConfigOrBuildError(
                code=30,
                message=f"Docker executable not found: {self.docker_bin}",
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ConfigOrBuildError(
                code=30,
                message=f"Build timed out: {exc}",
            ) from exc

        if result.returncode != 0:
            raise ConfigOrBuildError(
                code=30,
                message=(
                    f"Build failed (exit {result.returncode}): "
                    f"{result.stderr or result.stdout}"
                ),
            )

    def _verify_elf_x86_64(self, binary_path: Path) -> None:

        host_dir = self._docker_path(str(binary_path.parent.resolve()))
        bin_name = PurePosixPath(binary_path.name).as_posix()

        cmd = [
            self.docker_bin,
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{host_dir}:/bincheck:ro",
            self.image,
            "bash",
            "-lc",
            f"readelf -h /bincheck/{bin_name}",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise ConfigOrBuildError(
                code=30,
                message=f"ELF verification failed: {exc}",
            ) from exc

        if result.returncode != 0:
            raise ConfigOrBuildError(
                code=30,
                message=f"readelf failed for {binary_path}: {result.stderr}",
            )

        output = result.stdout
        if "ELF" not in output:
            raise ConfigOrBuildError(
                code=30,
                message=f"Binary is not ELF: {binary_path}",
            )
        if (
            "Machine:" in output
            and "Advanced Micro Devices X86-64" not in output
            and "X86-64" not in output
        ):
            if "x86-64" not in output.lower() and "amd64" not in output.lower():
                raise ConfigOrBuildError(
                    code=30,
                    message=f"Binary is not x86_64 ELF: {binary_path}\n{output}",
                )

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _shell_quote(value: str) -> str:
        return "'" + value.replace("'", "'\"'\"'") + "'"

    @staticmethod
    def _docker_path(host_path: str) -> str:

        p = host_path.replace("\\", "/")
        if len(p) >= 2 and p[1] == ":":
            return p
        return p
