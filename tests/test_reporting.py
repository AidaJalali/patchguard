import json
import os
import subprocess
import sys
from copy import deepcopy
from dataclasses import asdict
from itertools import combinations
from pathlib import Path

import pytest
from helpers import make_crash

from models import ReproducerArtifact
from orchestrator import COMPLETION_CHECKS, ReportValidationError, resolve_exit_code
from reporter.report_gen import make_report, write_reports


def complete(**updates):
    result = {
        "target_name": "fixture",
        **dict.fromkeys(COMPLETION_CHECKS, True),
        "findings": [{"finding_id": "fixed", "status": "Fixed"}],
    }
    result.update(updates)
    return result


@pytest.mark.parametrize(
    "statuses",
    [
        list(c)
        for n in range(6)
        for c in combinations(
            [
                "Fixed",
                "Incomplete Fix",
                "New Issue",
                "Functional Regression",
                "Inconclusive",
            ],
            n,
        )
    ],
)
def test_every_status_combination(statuses):
    data = complete(
        findings=[{"finding_id": str(i), "status": s} for i, s in enumerate(statuses)]
    )
    expected = (
        10
        if {"Incomplete Fix", "New Issue"} & set(statuses)
        else 20
        if "Functional Regression" in statuses
        else 40
        if "Inconclusive" in statuses
        else 0
    )
    assert resolve_exit_code(data) == expected
    data["errors"] = ["container failed"]
    assert resolve_exit_code(data) == 30


@pytest.mark.parametrize("key", COMPLETION_CHECKS)
def test_missing_completion_evidence_cannot_pass(key):
    data = complete()
    del data[key]
    assert resolve_exit_code(data) == 40
    data[key] = "true"
    with pytest.raises(ReportValidationError):
        resolve_exit_code(data)


def test_flaky_with_three_matching_replays_is_still_inconclusive():
    artifact = ReproducerArtifact(
        "fixed", "reproducers/fixed", "3/3", True, 13, 13, "input.bin"
    )
    assert resolve_exit_code(complete(reproducers=[asdict(artifact)])) == 40
    assert (
        resolve_exit_code(
            complete(
                reproducers=[asdict(artifact)],
                findings=[{"finding_id": "new", "status": "New Issue"}],
            )
        )
        == 10
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"findings": [{"finding_id": "x", "status": "Unknown"}]},
        {"findings": [{"finding_id": "x", "status": "Fixed"}] * 2},
        {"errors": "build failed"},
        {"errors": [False]},
        {"reproducers": [{"is_flaky": "false"}]},
        {"executions": [None]},
        {"schema_version": 2},
        {"schema_version": True},
        {"target_name": ""},
    ],
)
def test_reject_malformed_gate_evidence(updates):
    with pytest.raises(ReportValidationError):
        make_report(complete(**updates))


def test_report_preserves_all_evidence_and_does_not_mutate_input(tmp_path):
    data = complete(
        findings=[
            {
                "finding_id": "f1",
                "status": "New Issue",
                "evidence_explanation": "a|b\n<script>",
                "correlation": {"matched_functions": ["parse"], "confidence": "HIGH"},
            },
            {"finding_id": "f2", "status": "Functional Regression"},
        ],
        executions=[asdict(make_crash()), asdict(make_crash(build_type="release"))],
        reproducers=[
            asdict(
                ReproducerArtifact("f1", "bundles/f1", "3/3", False, 13, 3, "min.bin")
            )
        ],
        hardening_reports=[
            {
                "binary_path": "binary",
                "nx": {"enabled": True, "evidence": "RW"},
                "relro": "Full",
                "caveats": ["PIE does not prove ASLR"],
            }
        ],
        hardening_deltas=[
            {
                "protection": "PIE",
                "base_value": "True",
                "patched_value": "False",
                "severity": "HARDENING_REGRESSION",
            }
        ],
        custom_evidence={"nested": [1, 2, 3]},
    )
    before = deepcopy(data)
    out = tmp_path / "reports"
    report = write_reports(data, out / "report.json", out / "SUMMARY.md")
    saved = json.loads((out / "report.json").read_text())
    for key, value in before.items():
        assert saved[key] == value
    assert data == before
    assert report["exit_code"] == 10
    assert saved["finding_counts"] == {"New Issue": 1, "Functional Regression": 1}
    summary = (out / "SUMMARY.md").read_text()
    for snippet in (
        "release",
        "sanitized",
        "bundles/f1",
        "Full",
        "RW",
        "HARDENING_REGRESSION",
        "a&#124;b<br>&lt;script&gt;",
        "Functional Regression",
    ):
        assert snippet in summary


def test_same_report_paths_rejected(tmp_path):
    with pytest.raises(ValueError, match="must differ"):
        write_reports(complete(), tmp_path / "same", tmp_path / "same")
    assert not (tmp_path / "same").exists()


def test_hard_linked_report_outputs_rejected_unchanged(tmp_path):

    shared = tmp_path / "shared.out"
    shared.write_text("PRE-EXISTING\n")
    json_out = tmp_path / "report.json"
    os.link(shared, json_out)
    md_out = tmp_path / "SUMMARY.md"
    os.link(shared, md_out)
    before = shared.read_bytes()
    with pytest.raises(ValueError, match="must differ"):
        write_reports(complete(), json_out, md_out)
    assert shared.read_bytes() == before
    assert json_out.read_bytes() == before
    assert md_out.read_bytes() == before


def test_symlinked_report_outputs_rejected_unchanged(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("PRE-EXISTING\n")
    md_out = tmp_path / "SUMMARY.md"
    os.symlink(target, md_out)
    before = target.read_bytes()
    with pytest.raises(ValueError, match="must differ"):
        write_reports(complete(), target, md_out)
    assert target.read_bytes() == before


def test_relative_spelling_alias_rejected(tmp_path):
    json_out = tmp_path / "out.json"
    before_exists = json_out.exists()
    with pytest.raises(ValueError, match="must differ"):
        write_reports(complete(), json_out, tmp_path / "." / "out.json")
    assert json_out.exists() is before_exists


def test_cli_hard_linked_outputs_rejected_unchanged(tmp_path):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(complete()))
    shared = tmp_path / "shared.out"
    shared.write_text("PRE-EXISTING\n")
    json_out = tmp_path / "report.json"
    md_out = tmp_path / "SUMMARY.md"
    os.link(shared, json_out)
    os.link(shared, md_out)
    before = shared.read_bytes()
    result = invoke(
        tmp_path,
        "report",
        "--results",
        source,
        "--output-json",
        json_out,
        "--output-md",
        md_out,
    )
    assert result.returncode == 30
    assert "must differ" in result.stderr
    assert shared.read_bytes() == before


def invoke(tmp_path, *args):
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    return subprocess.run(
        [sys.executable, "-m", "patch_validator", *map(str, args)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    "data,expected",
    [
        (complete(), 0),
        ({"target_name": "partial"}, 40),
        (complete(errors=["build failed"]), 30),
        (complete(findings=[{"finding_id": "f", "status": "New Issue"}]), 10),
        (
            complete(findings=[{"finding_id": "f", "status": "Functional Regression"}]),
            20,
        ),
    ],
)
def test_cli_returns_exact_gate_code(tmp_path, data, expected):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(data))
    result = invoke(tmp_path, "report", "--results", source)
    assert result.returncode == expected, result.stderr
    assert json.loads((tmp_path / "report.json").read_text())["exit_code"] == expected
    assert (tmp_path / "SUMMARY.md").exists()


@pytest.mark.parametrize(
    "content", ["{bad", "[]", '{"target_name":"t","findings":[null]}']
)
def test_cli_rejects_invalid_input_without_traceback(tmp_path, content):
    source = tmp_path / "input.json"
    source.write_text(content)
    result = invoke(tmp_path, "report", "--results", source)
    assert result.returncode == 30
    assert "Traceback" not in result.stderr
    assert not (tmp_path / "report.json").exists()


def test_cli_does_not_overwrite_source(tmp_path):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(complete()))
    before = source.read_bytes()
    assert (
        invoke(
            tmp_path, "report", "--results", source, "--output-json", source
        ).returncode
        == 30
    )
    assert source.read_bytes() == before


def test_validate_json_output_must_not_alias_config(tmp_path):
    config = tmp_path / "target.yaml"
    config.write_text("targets:\n  - example\n")
    before = config.read_bytes()
    result = invoke(
        tmp_path,
        "validate",
        "--config",
        config,
        "--base",
        "old",
        "--patched",
        "new",
        "--output-json",
        config,
    )
    assert result.returncode == 30
    assert "must not overwrite the input config" in result.stderr
    assert config.read_bytes() == before


def test_validate_md_output_must_not_alias_config(tmp_path):
    config = tmp_path / "target.yaml"
    config.write_text("targets:\n  - example\n")
    before = config.read_bytes()
    result = invoke(
        tmp_path,
        "validate",
        "--config",
        config,
        "--base",
        "old",
        "--patched",
        "new",
        "--output-md",
        config,
    )
    assert result.returncode == 30
    assert config.read_bytes() == before


def test_validate_rejects_relative_alias_of_config(tmp_path):
    config = tmp_path / "target.yaml"
    config.write_text("targets:\n  - example\n")
    before = config.read_bytes()
    result = invoke(
        tmp_path,
        "validate",
        "--config",
        "target.yaml",
        "--base",
        "old",
        "--patched",
        "new",
        "--output-json",
        "./target.yaml",
    )
    assert result.returncode == 30
    assert config.read_bytes() == before


def test_validate_rejects_symlink_alias_of_config(tmp_path):
    config = tmp_path / "target.yaml"
    config.write_text("targets:\n  - example\n")
    link = tmp_path / "out_link.json"
    os.symlink(config, link)
    before = config.read_bytes()
    result = invoke(
        tmp_path,
        "validate",
        "--config",
        config,
        "--base",
        "old",
        "--patched",
        "new",
        "--output-json",
        link,
    )
    assert result.returncode == 30
    assert config.read_bytes() == before


def test_validate_rejects_hardlink_alias_of_config(tmp_path):
    config = tmp_path / "target.yaml"
    config.write_text("targets:\n  - example\n")
    hard = tmp_path / "hard_link.json"
    os.link(config, hard)
    before = config.read_bytes()
    result = invoke(
        tmp_path,
        "validate",
        "--config",
        config,
        "--base",
        "old",
        "--patched",
        "new",
        "--output-json",
        hard,
    )
    assert result.returncode == 30
    assert config.read_bytes() == before


def test_rejected_validate_leaves_all_files_unchanged(tmp_path):
    config = tmp_path / "target.yaml"
    config.write_text("targets:\n  - example\n")
    existing_output = tmp_path / "report.json"
    existing_output.write_text("PREVIOUS OUTPUT\n")
    before_config = config.read_bytes()
    before_output = existing_output.read_bytes()
    result = invoke(
        tmp_path,
        "validate",
        "--config",
        config,
        "--base",
        "old",
        "--patched",
        "new",
        "--output-json",
        config,
    )
    assert result.returncode == 30
    assert config.read_bytes() == before_config
    assert existing_output.read_bytes() == before_output


def test_report_input_protection_via_symlink_still_effective(tmp_path):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(complete()))
    link = tmp_path / "results_link.json"
    os.symlink(source, link)
    before = source.read_bytes()
    result = invoke(tmp_path, "report", "--results", source, "--output-json", link)
    assert result.returncode == 30
    assert source.read_bytes() == before


def test_validate_explicitly_reports_missing_integration(tmp_path):
    result = invoke(
        tmp_path,
        "validate",
        "--config",
        "target.yaml",
        "--base",
        "old",
        "--patched",
        "new",
    )
    assert result.returncode == 30
    summary = (tmp_path / "SUMMARY.md").read_text()
    assert "Configuration file not found" in summary
    assert json.loads((tmp_path / "report.json").read_text())["exit_code"] == 30


def test_help_and_argument_errors(tmp_path):
    assert invoke(tmp_path, "--help").returncode == 0
    assert invoke(tmp_path, "report").returncode == 30
