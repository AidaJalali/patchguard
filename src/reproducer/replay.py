from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
import sys
import uuid
from pathlib import Path


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv not in ([], ["minimized"]):
        print("usage: reproduce.sh [minimized]", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parent
    metadata = json.loads((root / "metadata.json").read_text())
    if hashlib.sha256((root / "binary").read_bytes()).hexdigest() != metadata["binary"]["sha256"]:
        print("binary hash does not match recorded evidence", file=sys.stderr)
        return 30
    execution = metadata["execution"]
    input_name = "minimized_input.bin" if argv else "crashing_input.bin"
    content = (root / input_name).read_bytes()
    mode = metadata["invocation"]["input_mode"]
    target_args = []
    for arg in metadata["invocation"]["argv_template"]:
        if arg != "{input}":
            target_args.append(arg)
        elif mode == "file":
            target_args.append("/bundle/" + input_name)
        else:
            text = content.decode("utf-8", errors="surrogateescape").strip(" \t\n")
            target_args.extend(re.split(r"[ \t\n]+", text) if text else [])
    name = "patchguard_replay_" + uuid.uuid4().hex
    command = [
        "docker", "run", "--rm", "--name", name, "--network", "none",
        f"--memory={execution['memory_mb']}m", f"--cpus={execution['cpus']}",
        "--pids-limit", str(execution["pids_limit"]), "--user", execution["user"],
        "-v", f"{root}:/bundle:ro", "-w", "/work",
    ]
    if mode == "stdin":
        command.append("-i")
    environment = shlex.join([
        "/usr/bin/env", *[f"{key}={value}" for key, value in metadata["build"]["configured_env"].items()],
    ])
    command.extend([
        "--entrypoint", "/bin/bash", execution["sandbox_image"], "-lc",
        '/bin/cp /bundle/binary /tmp/binary && /bin/chmod +x /tmp/binary && exec ' + environment + ' /tmp/binary "$@"',
        "replay", *target_args,
    ])
    try:
        return subprocess.run(
            command, input=content if mode == "stdin" else None,
            timeout=execution["timeout_sec"],
        ).returncode
    except subprocess.TimeoutExpired:
        print("replay exceeded the recorded time limit", file=sys.stderr)
        return 124
    except OSError as exc:
        print(f"replay infrastructure failed: {exc}", file=sys.stderr)
        return 30
    finally:
        try:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass


if __name__ == "__main__":
    raise SystemExit(main())
