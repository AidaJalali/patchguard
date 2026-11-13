# Person 4: reporting and integration

## Implemented independently

- `src/orchestrator.py`: result-contract validation and strict exit priority `30 > 10 > 20 > 40 > 0`.
- `src/reporter/report_gen.py`: `report.json` and `SUMMARY.md`, preserving all supplied evidence in JSON.
- `src/cli.py`, `src/patch_validator/`: `python -m patch_validator report` and a reserved `validate` command.
- `.github/workflows/patch_validation.yml`: unit/compiled-fixture tests and JUnit artifact upload. This is not yet the eight-scenario target validation pipeline.

## Upstream contract (schema version 1)

The `report` command accepts a JSON object. `examples/classified_results.json` is a deliberately incomplete example which exits 40; it is not a real validation result.

| Field | Producer / meaning |
| --- | --- |
| `target_name` | Required nonempty target identifier |
| `schema_version` | Version 1 (default if absent) |
| `findings` | Person 2: objects with unique `finding_id`, and `status`: `Fixed`, `Incomplete Fix`, `New Issue`, `Functional Regression`, or `Inconclusive`. Include correlation confidence, matched files/functions, and `evidence_explanation` as additional evidence. |
| `executions` | Person 1: `dataclasses.asdict(ExecutionResult)` objects, keeping release/sanitized and base/patched runs separate |
| `reproducers` | Person 3: `dataclasses.asdict(ReproducerArtifact)` objects; `is_flaky` is required and is authoritative even with `deterministic_replays="3/3"` |
| `hardening_reports` | Person 3: `dataclasses.asdict(HardeningReport)` objects |
| `hardening_deltas` | Person 3: `dataclasses.asdict(HardeningDelta)` objects; preserved and displayed as warnings, without inventing an unspecified gate policy |
| `errors` | Build/config/container failure messages; any message takes priority with exit 30 |
| `base_bug_reproduced` | Explicit boolean from verified base execution/replay evidence |
| `patch_fix_verified` | Explicit boolean from the classifier |
| `functional_tests_passed` | Explicit boolean from the independent functional oracle |
| `mandatory_checks_complete` | Explicit boolean from the eventual pipeline coordinator |

Lists default to empty; completion flags default to false. All four flags must be true for exit 0. Unknown statuses, duplicate finding IDs, and invalid gate-driving types are rejected. Additional JSON evidence is retained, including raw traces and correlations. Derived `exit_code`, `outcome`, and `finding_counts` are recomputed, never trusted from the input.

The report command consumes results; it does not independently establish that upstream claims are correct. A real orchestrator must populate completion flags only after their checks actually run.

## Usage

From the repository root:

```bash
PYTHONPATH=src .venv/bin/python -m patch_validator report \
  --results examples/classified_results.json \
  --output-json /tmp/patchguard-report/report.json \
  --output-md /tmp/patchguard-report/SUMMARY.md
# Expected exit: 40, because the example has no completed checks.
```

Python callers can use `write_reports(data, output_json, output_md)` and `resolve_exit_code(data)` directly. Output directories are created automatically. CLI argument/config/result errors return 30; `--help` returns 0.

The future interface is reserved:

```bash
PYTHONPATH=src .venv/bin/python -m patch_validator validate \
  --config target.yaml --base BASE_REF --patched PATCHED_REF
```

Until build/runner/classifier adapters are connected, it writes an explicit unavailable-pipeline error report and exits 30. It does not execute builds or return synthetic success.

## Remaining work

1. Agree on this contract with Persons 1 and 2; connect actual config, build, run, correlation, oracle, and classifier APIs.
2. Supply Person 3's actual artifacts and hardening comparison results.
3. Select and package two independent C/C++ targets, each with base/correct/incomplete/regression variants and independent oracles. Coordinate oracle approval and target eligibility with the TA before treating the benchmark selection as final.
4. Add `run_all_scenarios.sh` once executable target configs exist. Assert exact codes on real runs, including build-error and inconclusive cases.
5. Extend CI to execute that matrix, upload real reports/reproducer bundles, and publish summaries. Current CI checks module tests only; it has not been executed on GitHub during local development.
6. Rehearse unseen-patch onboarding and individual defense.
