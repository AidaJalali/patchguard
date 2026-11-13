from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

IMAGE = "patchguard-sandbox:latest"

VULN_C = textwrap.dedent(
    r"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char **argv) {
        if (argc < 2) {
            fprintf(stderr, "usage: %s <mode|payload>\n", argv[0]);
            return 1;
        }
        if (strcmp(argv[1], "hang") == 0) {
            for (;;) { /* intentional non-termination for timeout tests */ }
        }
        if (strcmp(argv[1], "segv") == 0) {
            int *p = NULL;
            *p = 42;
            return 0;
        }
        /* Vulnerable: unbounded copy into 8-byte heap buffer */
        char *buf = (char *)malloc(8);
        if (!buf) return 2;
        strcpy(buf, argv[1]);
        printf("ok:%s\n", buf);
        free(buf);
        return 0;
    }
    """
).lstrip()

PATCHED_C = textwrap.dedent(
    r"""
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int main(int argc, char **argv) {
        if (argc < 2) {
            fprintf(stderr, "usage: %s <mode|payload>\n", argv[0]);
            return 1;
        }
        if (strcmp(argv[1], "hang") == 0) {
            for (;;) { }
        }
        if (strcmp(argv[1], "segv") == 0) {
            /* Patched: reject null-deref trigger */
            fprintf(stderr, "segv mode disabled\n");
            return 0;
        }
        /* Patched: reject oversized payloads */
        if (strlen(argv[1]) >= 8) {
            fprintf(stderr, "input too long\n");
            return 1;
        }
        char *buf = (char *)malloc(8);
        if (!buf) return 2;
        memcpy(buf, argv[1], strlen(argv[1]) + 1);
        printf("ok:%s\n", buf);
        free(buf);
        return 0;
    }
    """
).lstrip()


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture
def vuln_repo(tmp_path: Path) -> Path:

    repo = tmp_path / "vuln_target"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@patchguard.local")
    _git(repo, "config", "user.name", "PatchGuard Test")

    (repo / "vuln.c").write_text(VULN_C, encoding="utf-8")
    _git(repo, "add", "vuln.c")
    _git(repo, "commit", "-m", "base: vulnerable")
    base_ref = _git(repo, "rev-parse", "HEAD")

    (repo / "vuln.c").write_text(PATCHED_C, encoding="utf-8")
    _git(repo, "add", "vuln.c")
    _git(repo, "commit", "-m", "patched: bounds check")
    patched_ref = _git(repo, "rev-parse", "HEAD")

    repo_meta = repo / ".patchguard_refs"
    repo_meta.write_text(f"{base_ref}\n{patched_ref}\n", encoding="utf-8")
    return repo


def vuln_refs(repo: Path) -> tuple[str, str]:
    lines = (repo / ".patchguard_refs").read_text(encoding="utf-8").splitlines()
    return lines[0], lines[1]


def make_config_dict(repo: Path, **overrides) -> dict:
    base_ref, patched_ref = vuln_refs(repo)
    data = {
        "target_name": "vuln",
        "repo_path": str(repo),
        "base_ref": base_ref,
        "patched_ref": patched_ref,
        "build_cmd_release": "gcc -O2 -o vuln vuln.c",
        "build_cmd_sanitized": (
            "gcc -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fsanitize=address,undefined -fno-omit-frame-pointer "
            "-g -O1 -o vuln vuln.c"
        ),
        "binary_rel_path": "vuln",
        "input_mode": "args",
        "timeout_sec": 2.0,
        "memory_mb": 256,
        "cpus": 1.0,
    }
    data.update(overrides)
    return data


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=20,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def image_present(image: str = IMAGE) -> bool:
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=20,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


requires_docker = pytest.mark.skipif(
    not docker_available() or not image_present(),
    reason=f"Docker and image {IMAGE} required",
)
