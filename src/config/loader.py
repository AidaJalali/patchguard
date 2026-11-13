from __future__ import annotations

import json
import math
import os
import re
from pathlib import Path
from typing import Any, Dict

import yaml

from exceptions import ConfigOrBuildError
from models import TargetConfig, TestSpec, ValidationConfig

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
TEST_KINDS = ("functional", "boundary", "security")
STDOUT_KINDS = ("exact", "regex", "json", "none")
_TEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def load_target_config(config_path: str) -> TargetConfig:

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

    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return json.loads(text)


def _validate_and_build(data: Dict[str, Any]) -> TargetConfig:
    missing = [
        key for key in REQUIRED_KEYS if key not in data or data[key] in (None, "")
    ]
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

    try:
        timeout_sec = float(data.get("timeout_sec", 5.0))
    except (TypeError, ValueError) as exc:
        raise ConfigOrBuildError(code=30, message=f"timeout_sec must be a finite number: {exc}") from exc
    if not math.isfinite(timeout_sec) or timeout_sec <= 0:
        raise ConfigOrBuildError(
            code=30,
            message=f"timeout_sec must be a finite number > 0, got {timeout_sec}",
        )

    try:
        memory_mb = int(data.get("memory_mb", 512))
    except (TypeError, ValueError) as exc:
        raise ConfigOrBuildError(code=30, message=f"memory_mb must be an integer: {exc}") from exc
    if memory_mb < 64:
        raise ConfigOrBuildError(
            code=30,
            message=f"memory_mb must be >= 64, got {memory_mb}",
        )

    try:
        cpus = float(data.get("cpus", 1.0))
    except (TypeError, ValueError) as exc:
        raise ConfigOrBuildError(code=30, message=f"cpus must be a finite number: {exc}") from exc
    if not math.isfinite(cpus) or cpus <= 0:
        raise ConfigOrBuildError(
            code=30,
            message=f"cpus must be a finite number > 0, got {cpus}",
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
            input_mode=input_mode,
            timeout_sec=timeout_sec,
            memory_mb=memory_mb,
            cpus=cpus,
            env_vars=env_vars,
            functional_tests_path=str(data.get("functional_tests_path", "")),
            security_tests_path=str(data.get("security_tests_path", "")),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigOrBuildError(
            code=30,
            message=f"Invalid configuration values: {exc}",
        ) from exc


def load_validation_config(config_path: str) -> ValidationConfig:
    path = Path(config_path)
    if not path.is_file():
        raise ConfigOrBuildError(
            code=30,
            message=f"Configuration file not found: {config_path}",
        )
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigOrBuildError(code=30, message=f"Unable to read configuration file: {exc}") from exc
    try:
        data = _parse_config_text(raw_text, path.suffix.lower())
    except (yaml.YAMLError, json.JSONDecodeError, ValueError) as exc:
        raise ConfigOrBuildError(code=30, message=f"Failed to parse configuration file: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigOrBuildError(code=30, message="Configuration root must be a mapping/object")

    target = _validate_and_build(data)
    target_name = target.target_name

    raw_tests = data.get("tests")
    if not isinstance(raw_tests, list) or not raw_tests:
        raise ConfigOrBuildError(code=30, message="'tests' must be a nonempty list of test objects")
    tests, seen = [], set()
    for index, item in enumerate(raw_tests):
        tests.append(_validate_test(item, index, target.input_mode, seen))

    argv_template = data.get("argv_template")
    if argv_template is not None:
        if not isinstance(argv_template, list) or any(
            not isinstance(a, str) or "\0" in a for a in argv_template
        ):
            raise ConfigOrBuildError(code=30, message="argv_template must be a list of strings without null bytes")
        expected = 0 if target.input_mode == "stdin" else 1
        if argv_template.count("{input}") != expected:
            raise ConfigOrBuildError(
                code=30,
                message=f"argv_template must contain exactly {'no' if expected == 0 else 'one'} "
                        f"{{input}} placeholder for {target.input_mode} mode",
            )

    oracle_source = data.get("oracle_source")
    if not isinstance(oracle_source, str) or not oracle_source.strip():
        raise ConfigOrBuildError(
            code=30,
            message="oracle_source is required: a nonempty record of where the expected behavior comes from",
        )

    repo = Path(target.repo_path).resolve()
    for label, raw in (("work_dir", data.get("work_dir")), ("output_dir", data.get("output_dir"))):
        if not isinstance(raw, str) or not raw.strip():
            raise ConfigOrBuildError(code=30, message=f"{label} must be a nonempty path string")
        resolved = Path(os.path.abspath(raw)).resolve()
        if resolved == repo or repo in resolved.parents:
            raise ConfigOrBuildError(
                code=30,
                message=f"{label} ({raw}) must not live inside the target repo ({repo})",
            )

    return ValidationConfig(
        target=target,
        argv_template=list(argv_template) if argv_template is not None else None,
        oracle_source=oracle_source.strip(),
        work_dir=os.path.abspath(str(data["work_dir"])),
        output_dir=os.path.abspath(str(data["output_dir"])),
        tests=tests,
    )


def _validate_test(item: Any, index: int, input_mode: str, seen: set[str]) -> TestSpec:
    where = f"test at index {index}"
    if not isinstance(item, dict):
        raise ConfigOrBuildError(code=30, message=f"{where}: must be an object")
    test_id = item.get("id")
    if not isinstance(test_id, str) or not test_id.strip():
        raise ConfigOrBuildError(code=30, message=f"{where}: 'id' must be a nonempty string")
    test_id = test_id.strip()
    if not _TEST_ID_RE.fullmatch(test_id):
        raise ConfigOrBuildError(
            code=30,
            message=f"{where}: test id {test_id!r} must match [A-Za-z0-9][A-Za-z0-9._-]*",
        )
    if test_id in seen:
        raise ConfigOrBuildError(code=30, message=f"duplicate test id '{test_id}'")
    seen.add(test_id)

    kind = item.get("kind")
    if kind not in TEST_KINDS:
        raise ConfigOrBuildError(
            code=30,
            message=f"{where} ({test_id}): 'kind' must be one of {TEST_KINDS}, got {kind!r}",
        )

    if "input_hex" in item:
        try:
            input_bytes = bytes.fromhex(str(item["input_hex"]))
        except ValueError as exc:
            raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): invalid input_hex: {exc}") from exc
    elif "input" in item:
        raw_input = item["input"]
        if not isinstance(raw_input, str):
            raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): 'input' must be a string (use input_hex for binary)")
        input_bytes = raw_input.encode("utf-8")
    else:
        raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): 'input' or 'input_hex' is required")
    if input_mode == "args" and b"\0" in input_bytes:
        raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): argv inputs cannot contain null bytes")

    expected_exit_code = item.get("expected_exit_code")
    if expected_exit_code is not None and (
        isinstance(expected_exit_code, bool) or not isinstance(expected_exit_code, int)
    ):
        raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): expected_exit_code must be an integer or null")
    if kind in ("functional", "boundary") and (
        isinstance(expected_exit_code, bool) or not isinstance(expected_exit_code, int)
    ):
        raise ConfigOrBuildError(
            code=30,
            message=f"{where} ({test_id}): {kind} tests require an explicit integer expected_exit_code",
        )

    is_valid_input = item.get("is_valid_input", False)
    if type(is_valid_input) is not bool:
        raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): is_valid_input must be a boolean")

    stdout_kind = item.get("stdout_kind", "none")
    if stdout_kind not in STDOUT_KINDS:
        raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): stdout_kind must be one of {STDOUT_KINDS}")

    stdout_value = item.get("stdout_value")
    if stdout_kind == "exact":
        if not isinstance(stdout_value, str):
            raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): stdout_kind 'exact' requires a string stdout_value")
    elif stdout_kind == "regex":
        if not isinstance(stdout_value, str):
            raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): stdout_kind 'regex' requires a string stdout_value")
        try:
            re.compile(stdout_value)
        except re.error as exc:
            raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): invalid stdout regex: {exc}") from exc
    elif stdout_kind == "none":
        if stdout_value is not None:
            raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): stdout_kind 'none' must not carry stdout_value")

    stderr_pattern = item.get("stderr_pattern")
    if stderr_pattern is not None:
        if not isinstance(stderr_pattern, str):
            raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): stderr_pattern must be a string or null")
        try:
            re.compile(stderr_pattern)
        except re.error as exc:
            raise ConfigOrBuildError(code=30, message=f"{where} ({test_id}): invalid stderr_pattern regex: {exc}") from exc

    base_expect = item.get("base_expect")
    patched_expect = item.get("patched_expect")
    for label, value in (("base_expect", base_expect), ("patched_expect", patched_expect)):
        if value is not None:
            if not isinstance(value, dict) or type(value.get("crash")) is not bool:
                raise ConfigOrBuildError(
                    code=30,
                    message=f"{where} ({test_id}): {label} must be an object with a boolean 'crash' field",
                )
            if not value["crash"] and (
                isinstance(value.get("exit_code"), bool) or not isinstance(value.get("exit_code"), int)
            ):
                raise ConfigOrBuildError(
                    code=30,
                    message=f"{where} ({test_id}): {label} with crash=false requires an integer exit_code",
                )
    if kind == "security" and (base_expect is None or patched_expect is None):
        raise ConfigOrBuildError(
            code=30,
            message=f"{where} ({test_id}): security tests require explicit base_expect and patched_expect",
        )

    return TestSpec(
        id=test_id,
        kind=kind,
        input_bytes=input_bytes,
        expected_exit_code=expected_exit_code,
        is_valid_input=is_valid_input,
        stdout_kind=stdout_kind,
        stdout_value=stdout_value,
        stderr_pattern=stderr_pattern,
        base_expect=base_expect,
        patched_expect=patched_expect,
    )
