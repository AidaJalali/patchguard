from copy import deepcopy

from models import (
    EXIT_BUILD_OR_CONFIG_ERROR,
    EXIT_FUNC_REGRESSION,
    EXIT_INCONCLUSIVE,
    EXIT_PASS,
    EXIT_VULN_REMAINS,
    STATUS_FIXED,
    STATUS_FUNCTIONAL_REGRESSION,
    STATUS_INCOMPLETE_FIX,
    STATUS_INCONCLUSIVE,
    STATUS_NEW_ISSUE,
)

STATUSES = (
    STATUS_FIXED,
    STATUS_INCOMPLETE_FIX,
    STATUS_NEW_ISSUE,
    STATUS_FUNCTIONAL_REGRESSION,
    STATUS_INCONCLUSIVE,
)
COMPLETION_CHECKS = (
    "base_bug_reproduced",
    "patch_fix_verified",
    "functional_tests_passed",
    "mandatory_checks_complete",
)


class ReportValidationError(ValueError):
    pass


def validate_result(data: dict) -> dict:

    if not isinstance(data, dict):
        raise ReportValidationError("result must be a JSON object")
    result = deepcopy(data)
    if (
        not isinstance(result.get("target_name"), str)
        or not result["target_name"].strip()
    ):
        raise ReportValidationError("target_name must be a nonempty string")
    if result.get("schema_version", 1) != 1 or isinstance(
        result.get("schema_version"), bool
    ):
        raise ReportValidationError("unsupported schema_version (expected 1)")
    result["schema_version"] = 1
    for key in (
        "findings",
        "executions",
        "reproducers",
        "hardening_reports",
        "hardening_deltas",
        "errors",
    ):
        result.setdefault(key, [])
        if not isinstance(result[key], list):
            raise ReportValidationError(f"{key} must be a list")
    for key in COMPLETION_CHECKS:
        result.setdefault(key, False)
        if type(result[key]) is not bool:
            raise ReportValidationError(f"{key} must be a boolean")
    ids = set()
    for finding in result["findings"]:
        if not isinstance(finding, dict):
            raise ReportValidationError("findings must contain objects")
        fid = finding.get("finding_id")
        if not isinstance(fid, str) or not fid or fid in ids:
            raise ReportValidationError("finding_id must be nonempty and unique")
        ids.add(fid)
        if finding.get("status") not in STATUSES:
            raise ReportValidationError(f"unknown finding status for {fid}")
    for artifact in result["reproducers"]:
        if not isinstance(artifact, dict) or type(artifact.get("is_flaky")) is not bool:
            raise ReportValidationError("reproducers require a boolean is_flaky")
    for key in ("executions", "hardening_reports", "hardening_deltas"):
        if any(not isinstance(item, dict) for item in result[key]):
            raise ReportValidationError(f"{key} must contain objects")
    if any(
        not isinstance(error, str) or not error.strip() for error in result["errors"]
    ):
        raise ReportValidationError(
            "errors must contain nonempty messages (build/config/container)"
        )
    return result


def resolve_exit_code(data: dict) -> int:

    result = validate_result(data)
    if result["errors"]:
        return EXIT_BUILD_OR_CONFIG_ERROR
    statuses = {finding["status"] for finding in result["findings"]}
    if statuses & {STATUS_INCOMPLETE_FIX, STATUS_NEW_ISSUE}:
        return EXIT_VULN_REMAINS
    if STATUS_FUNCTIONAL_REGRESSION in statuses:
        return EXIT_FUNC_REGRESSION
    if (
        STATUS_INCONCLUSIVE in statuses
        or any(artifact["is_flaky"] for artifact in result["reproducers"])
        or not all(result[key] for key in COMPLETION_CHECKS)
    ):
        return EXIT_INCONCLUSIVE
    return EXIT_PASS
