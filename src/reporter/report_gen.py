import json
from collections import Counter
from pathlib import Path

from orchestrator import resolve_exit_code, validate_result
from paths import paths_alias

EXIT_LABELS = {
    0: "PASS",
    10: "VULN_REMAINS / NEW_ISSUE",
    20: "FUNC_REGRESSION",
    30: "BUILD_OR_CONFIG_ERROR",
    40: "INCONCLUSIVE",
}


def make_report(data: dict) -> dict:
    result = validate_result(data)
    result["exit_code"] = resolve_exit_code(result)
    result["outcome"] = EXIT_LABELS[result["exit_code"]]
    result["finding_counts"] = dict(Counter(f["status"] for f in result["findings"]))
    return result


def _cell(value) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "&#124;")
        .replace("\r", " ")
        .replace("\n", "<br>")
    )


def render_summary(report: dict) -> str:
    report = make_report(report)
    lines = [
        f"# Patch validation: {_cell(report['target_name'])}",
        "",
        f"**{report['outcome']}** — exit code `{report['exit_code']}`",
        "",
        "## Completion checks",
        "",
    ]
    from orchestrator import COMPLETION_CHECKS

    lines.extend(
        f"- {key}: {'yes' if report[key] else 'no'}" for key in COMPLETION_CHECKS
    )
    if report["errors"]:
        lines += ["", "## Build/config/container errors", ""]
        lines.extend(f"- {_cell(error)}" for error in report["errors"])
    lines += [
        "",
        "## Findings",
        "",
        "| Finding | Status | Evidence |",
        "| --- | --- | --- |",
    ]
    for finding in report["findings"]:
        lines.append(
            "| "
            + " | ".join(
                _cell(finding.get(key, ""))
                for key in ("finding_id", "status", "evidence_explanation")
            )
            + " |"
        )
    lines += [
        "",
        "## Execution evidence",
        "",
        "| Test | Version | Build | Exit | Crash | Timeout | OOM | Error |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for execution in report["executions"]:
        lines.append(
            "| "
            + " | ".join(
                _cell(execution.get(key, ""))
                for key in (
                    "test_id",
                    "version",
                    "build_type",
                    "exit_code",
                    "crashed",
                    "timed_out",
                    "oom_killed",
                    "error_type",
                )
            )
            + " |"
        )
    lines += [
        "",
        "## Reproducers",
        "",
        "| Finding | Replays | Flaky/inconclusive | Bundle | Input sizes |",
        "| --- | --- | --- | --- | --- |",
    ]
    for artifact in report["reproducers"]:
        values = [
            artifact.get("finding_id", ""),
            artifact.get("deterministic_replays", ""),
            artifact["is_flaky"],
            artifact.get("bundle_dir", ""),
            f"{artifact.get('original_size_bytes', '?')} → {artifact.get('minimized_size_bytes', '?')}",
        ]
        lines.append("| " + " | ".join(map(_cell, values)) + " |")
    lines += [
        "",
        "## Binary hardening",
        "",
        "| Binary | NX | PIE | RELRO | Canary |",
        "| --- | --- | --- | --- | --- |",
    ]
    for hardening in report["hardening_reports"]:

        def protection(key):
            check = hardening.get(key, {})
            return (
                f"{check.get('enabled', 'unknown')}: {check.get('evidence', '')}"
                if isinstance(check, dict)
                else check
            )

        values = [
            hardening.get("binary_path", ""),
            protection("nx"),
            protection("pie"),
            f"{hardening.get('relro', 'unknown')}: {hardening.get('relro_evidence', '')}",
            protection("canary"),
        ]
        lines.append("| " + " | ".join(map(_cell, values)) + " |")
        lines.extend(f"\nNote: {_cell(note)}" for note in hardening.get("caveats", []))
    for delta in report["hardening_deltas"]:
        lines.append(
            f"\n- {_cell(delta.get('severity', ''))}: {_cell(delta.get('protection', ''))} "
            f"{_cell(delta.get('base_value', ''))} → {_cell(delta.get('patched_value', ''))}"
        )
    lines += [
        "",
        "Full stack traces, correlations, and additional evidence are preserved in report.json.",
        "",
    ]
    return "\n".join(lines)


def write_reports(data: dict, output_json: str | Path, output_md: str | Path) -> dict:
    report = make_report(data)
    json_path, md_path = Path(output_json), Path(output_md)
    if paths_alias(json_path, md_path):
        raise ValueError("JSON and Markdown output paths must differ")

    payload = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    summary = render_summary(report)
    for path, content in ((json_path, payload), (md_path, summary)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return report
