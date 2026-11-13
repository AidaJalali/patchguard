from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from builder.builder import DualBuilder
from classifier.verdict import classify_pair
from config.loader import load_validation_config
from correlator.correlator import DiffCorrelation, correlate
from exceptions import ConfigOrBuildError
from hardening.elf_checker import compare_hardening, inspect_elf
from diff_parser.diff_analyzer import analyze_git
from models import (
    TestSpec,
    ValidationConfig,
)
from oracle.functional_oracle import OracleExpectation, evaluate
from regression_gen.generator import (
    RegressionExpectation,
    VersionExpectation,
    promote_to_regression_suite,
    verify_manifest_entry,
)
from reporter.report_gen import write_reports
from reproducer.bundler import FindingContext, build_reproducer, verify_reproducibility
from runner.adapter import TargetRunnerAdapter

BUILD_TYPES = ("release", "sanitized")


def run_validation(config_path, output_json, output_md) -> dict:
    try:
        cfg = load_validation_config(config_path)
    except ConfigOrBuildError as exc:
        return _write_failure(config_path, output_json, output_md, exc.message)
    state = {"data": None}
    try:
        return _run_pipeline(cfg, output_json, output_md, state)
    except ConfigOrBuildError as exc:
        return _failure_from_state(config_path, state, output_json, output_md, exc.message)
    except (OSError, ValueError) as exc:
        return _failure_from_state(
            config_path, state, output_json, output_md, f"pipeline failed: {exc}"
        )


def _write_failure(config_path, output_json, output_md, message) -> dict:
    name = Path(config_path).stem or "unconfigured"
    data = {
        "target_name": name,
        "errors": [message],
        "findings": [],
        "executions": [],
        "reproducers": [],
        "hardening_reports": [],
        "hardening_deltas": [],
        "base_bug_reproduced": False,
        "patch_fix_verified": False,
        "functional_tests_passed": False,
        "mandatory_checks_complete": False,
    }
    return write_reports(data, output_json, output_md)


def _failure_from_state(config_path, state, output_json, output_md, message) -> dict:
    data = state.get("data")
    if data is None:
        return _write_failure(config_path, output_json, output_md, message)
    data["errors"].append(message)
    data["mandatory_checks_complete"] = False
    data["patch_fix_verified"] = False
    return write_reports(data, output_json, output_md)


def _run_pipeline(cfg: ValidationConfig, output_json, output_md, state=None) -> dict:
    data = {
        "target_name": cfg.target.target_name,
        "oracle_source": cfg.oracle_source,
        "findings": [],
        "executions": [],
        "reproducers": [],
        "hardening_reports": [],
        "hardening_deltas": [],
        "regression_entries": [],
        "errors": [],
        "base_bug_reproduced": False,
        "patch_fix_verified": False,
        "functional_tests_passed": False,
        "mandatory_checks_complete": False,
    }
    if state is not None:
        state["data"] = data

    builder = DualBuilder()
    artifacts = builder.build_all(cfg.target, cfg.work_dir)

    base_release = inspect_elf(artifacts[("base", "release")].binary_path)
    patched_release = inspect_elf(artifacts[("patched", "release")].binary_path)
    data["hardening_reports"] = [asdict(base_release), asdict(patched_release)]
    data["hardening_deltas"] = [
        asdict(delta)
        for delta in compare_hardening(base_release, patched_release)
    ]

    patch = analyze_git(cfg.target.repo_path, cfg.target.base_ref, cfg.target.patched_ref)
    if patch.diagnostics:
        raise ConfigOrBuildError(code=30, message=f"source analysis failed: {'; '.join(patch.diagnostics)}")

    functional_total = 0
    functional_failures = []

    for spec in cfg.tests:
        adapter = TargetRunnerAdapter(
            artifacts,
            cfg.target,
            test_id=spec.id,
            argv_template=cfg.argv_template,
        )
        oracle = _make_oracle(spec)
        for build_type in BUILD_TYPES:
            base = adapter.run(
                spec.input_bytes, version="base", build_type=build_type,
                timeout_sec=cfg.target.timeout_sec,
            )
            patched = adapter.run(
                spec.input_bytes, version="patched", build_type=build_type,
                timeout_sec=cfg.target.timeout_sec,
            )
            data["executions"].append(asdict(base))
            data["executions"].append(asdict(patched))
            if spec.kind == "functional":
                functional_total += 1
                if not (oracle and evaluate(patched, oracle).passed):
                    functional_failures.append(f"{spec.id}-{build_type}")

            base_oracle = evaluate(base, oracle) if oracle else None
            patched_oracle = evaluate(patched, oracle) if oracle else None

            interesting = (
                base.crashed
                or patched.crashed
                or (
                    base_oracle is not None
                    and patched_oracle is not None
                    and base_oracle.is_valid_input
                    and base_oracle.passed
                    and not patched_oracle.passed
                )
            )
            if not interesting:
                continue

            finding_id = f"{spec.id}-{build_type}"
            base_replay, base_artifact = _crash_evidence(
                finding_id, spec, base, build_type, cfg, adapter, artifacts, output_root=f"{cfg.output_dir}/reproducers"
            )
            patched_replay, patched_artifact = _crash_evidence(
                finding_id, spec, patched, build_type, cfg, adapter, artifacts, output_root=f"{cfg.output_dir}/reproducers"
            )
            if base_artifact is not None:
                data["reproducers"].append(asdict(base_artifact))
            if patched_artifact is not None:
                data["reproducers"].append(asdict(patched_artifact))

            if base.crashed:
                correlation = correlate(finding_id, base, patch)
            elif patched.crashed:
                correlation = correlate(finding_id, patched, patch)
            else:
                correlation = DiffCorrelation(finding_id, "INCONCLUSIVE")

            finding = classify_pair(
                finding_id,
                base,
                patched,
                correlation=correlation,
                base_oracle=base_oracle,
                patched_oracle=patched_oracle,
                base_replay=base_replay,
                patched_replay=patched_replay,
                base_artifact=base_artifact,
                patched_artifact=patched_artifact,
            )

            if finding.status == "Inconclusive" and not (base.crashed or patched.crashed):
                continue
            data["findings"].append(finding.to_dict())

            if base_artifact is not None and not base_artifact.is_flaky:
                _promote_regression(
                    spec, base_artifact, adapter, cfg, data["regression_entries"]
                )

    data["base_bug_reproduced"] = any(
        finding["status"] in ("Fixed", "Incomplete Fix") for finding in data["findings"]
    )
    data["patch_fix_verified"] = any(
        finding["status"] == "Fixed" for finding in data["findings"]
    )
    data["functional_tests_passed"] = functional_total > 0 and not functional_failures
    data["mandatory_checks_complete"] = True
    return write_reports(data, output_json, output_md)


def _make_oracle(spec: TestSpec):
    if spec.expected_exit_code is None:
        return None
    kind = spec.stdout_kind
    value = spec.stdout_value
    if kind == "none":
        kind, value = "exact", ""
    return OracleExpectation(
        spec.id,
        spec.expected_exit_code,
        spec.is_valid_input,
        kind,
        value,
        spec.stderr_pattern,
    )


def _crash_evidence(finding_id, spec, result, build_type, cfg, adapter, artifacts, *, output_root):
    if not result.crashed:
        return None, None
    replay = verify_reproducibility(
        adapter, spec.input_bytes, result, finding_id=finding_id,
        timeout_sec=cfg.target.timeout_sec,
    )
    context = FindingContext(
        finding_id=finding_id,
        input_bytes=spec.input_bytes,
        original=result,
        binary_path=Path(artifacts[(result.version, result.build_type)].binary_path),
        input_mode=cfg.target.input_mode,
        argv_template=list(adapter.argv_template),
        cli_command=result.cli_command,
        base_commit_hash=artifacts[("base", build_type)].commit_hash,
        patched_commit_hash=artifacts[("patched", build_type)].commit_hash,
        compile_flags=artifacts[(result.version, build_type)].compile_flags,
        env_vars=cfg.target.env_vars,
    )
    artifact = build_reproducer(context, adapter, output_root=output_root)
    return replay, artifact


def _promote_regression(spec, artifact, adapter, cfg, regression_entries):
    expectation = RegressionExpectation(
        base=_expectation_from_dict(spec.base_expect),
        patched=_expectation_from_dict(spec.patched_expect),
    )
    entry = promote_to_regression_suite(
        artifact, expectation, suite_root=f"{cfg.output_dir}/regression_suite",
        replace=True,
    )
    minimized = Path(entry.source_bundle, "minimized_input.bin").read_bytes()
    verified = verify_manifest_entry(
        adapter, entry, minimized, timeout_sec=cfg.target.timeout_sec
    )
    regression_entries.append(
        {"finding_id": entry.finding_id, "verified": verified.ok}
    )


def _expectation_from_dict(data: dict | None) -> VersionExpectation:
    if data is None:
        return VersionExpectation(crash=False, exit_code=0)
    return VersionExpectation(
        crash=data.get("crash", False),
        exit_code=data.get("exit_code"),
    )
