"""Load and validate target_config.yaml / JSON into TargetConfig."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

import yaml

from src.exceptions import ConfigOrBuildError
from src.models import InputMode, TargetConfig

REQUIRED_KEYS = (
    "target_name",
    "repo_path",
    "base_ref",
    "patched_ref",
    "build_cmd_release",
    "build_cmd_sanitized",
    "binary_rel_path",
    "input_mode",
)

VALID_INPUT_MODES = ("stdin", "file", "args")


def load_target_config(config_path: str) -> TargetConfig:
    """Parse and validate a YAML or JSON target configuration file."""
    path = Path(config_path)
    if not path.is_file():
        raise ConfigOrBuildError(
            code=30,
            message=f"Configuration file not found: {config_path}",
        )

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigOrBuildError(
            code=30,
            message=f"Unable to read configuration file: {exc}",
        ) from exc

    try:
        data = _parse_config_text(raw_text, path.suffix.lower())
    except (yaml.YAMLError, json.JSONDecodeError, ValueError) as exc:
        raise ConfigOrBuildError(
            code=30,
            message=f"Failed to parse configuration file: {exc}",
        ) from exc

    if not isinstance(data, dict):
        raise ConfigOrBuildError(
            code=30,
            message="Configuration root must be a mapping/object",
        )

    return _validate_and_build(data)


def _parse_config_text(text: str, suffix: str) -> Any:
    if suffix in (".yaml", ".yml"):
        return yaml.safe_load(text)
    if suffix == ".json":
        return json.loads(text)
    # Default: try YAML first, then JSON.
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return json.loads(text)


def _validate_and_build(data: Dict[str, Any]) -> TargetConfig:
    missing = [key for key in REQUIRED_KEYS if key not in data or data[key] in (None, "")]
    if missing:
        raise ConfigOrBuildError(
            code=30,
            message=f"Missing required configuration keys: {', '.join(missing)}",
        )

    input_mode = data["input_mode"]
    if input_mode not in VALID_INPUT_MODES:
        raise ConfigOrBuildError(
            code=30,
            message=f"Invalid input_mode '{input_mode}'; must be one of {VALID_INPUT_MODES}",
        )

    timeout_sec = float(data.get("timeout_sec", 5.0))
    if timeout_sec <= 0:
        raise ConfigOrBuildError(
            code=30,
            message=f"timeout_sec must be > 0, got {timeout_sec}",
        )

    memory_mb = int(data.get("memory_mb", 512))
    if memory_mb < 64:
        raise ConfigOrBuildError(
            code=30,
            message=f"memory_mb must be >= 64, got {memory_mb}",
        )

    repo_path = str(data["repo_path"])
    if not os.path.isdir(repo_path):
        raise ConfigOrBuildError(
            code=30,
            message=f"repo_path does not exist or is not a directory: {repo_path}",
        )

    env_vars = data.get("env_vars") or {}
    if not isinstance(env_vars, dict):
        raise ConfigOrBuildError(
            code=30,
            message="env_vars must be a mapping of string to string",
        )
    env_vars = {str(k): str(v) for k, v in env_vars.items()}

    try:
        return TargetConfig(
            target_name=str(data["target_name"]),
            repo_path=os.path.abspath(repo_path),
            base_ref=str(data["base_ref"]),
            patched_ref=str(data["patched_ref"]),
            build_cmd_release=str(data["build_cmd_release"]),
            build_cmd_sanitized=str(data["build_cmd_sanitized"]),
            binary_rel_path=str(data["binary_rel_path"]),
            input_mode=input_mode,  # type: ignore[arg-type]
            timeout_sec=timeout_sec,
            memory_mb=memory_mb,
            cpus=float(data.get("cpus", 1.0)),
            env_vars=env_vars,
            functional_tests_path=str(data.get("functional_tests_path", "")),
            security_tests_path=str(data.get("security_tests_path", "")),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigOrBuildError(
            code=30,
            message=f"Invalid configuration values: {exc}",
        ) from exc
