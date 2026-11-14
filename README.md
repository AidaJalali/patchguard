# patchguard
Automated security patch validation and regression testing for C/C++ applications in CI/CD pipelines.

## Development

Python 3.12:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest          # run the test suite
PYTHONPATH=src .venv/bin/python ... # ad-hoc runs (pytest sets src on the path itself)
```

Modules (Person 3 — Reproducibility, Minimizer & Hardening Lead):

- `src/models.py` — shared dataclasses and contracts (task T0)
- `src/hardening/elf_checker.py` — NX / PIE / RELRO / Canary inspection + Base-vs-Patched downgrade detection (T3.4)
- `src/minimizer/ddmin.py` — Delta Debugging minimizer with crash-signature equivalence predicate (T3.2)
- `src/reproducer/bundler.py` — 3× replay verifier, ddmin integration, self-contained `reproducers/<finding_id>/` bundle with standalone `reproduce.sh` (T3.1)
- `src/regression_gen/generator.py` — promotes verified minimized inputs into `<suite_root>/auto_generated/` with an atomic `manifest.json`, plus `verify_regression()`/`verify_manifest_entry()` re-checking helpers (T3.3). Inputs are content-addressed (`<finding_id>_minimized_<sha256[0:16]>.bin`) and the manifest is published atomically only after the input lands, so a failed publish leaves the previous suite fully usable; `verify_manifest_entry()` hashes inputs against the manifest before any execution, and replay evidence is validated record-by-record before promotion

Crash equivalence rule (shared by replay verification and minimization, `strict_crash_match` in `src/models.py`): a match requires `crashed=True`, no timeout/OOM kill, an error type, and the same top frame — line info is compared only when both sides have it. Insufficient diagnostics, nondeterministic replays, or a failed minimization revalidation skip minimization (original input kept as fallback) and mark the finding inconclusive (exit code 40 downstream). In generated `reproduce.sh`, target env vars are applied only to the child process via `env`, so they can never overwrite script internals.

Cross-module contracts from the combined review:

- **Replay provenance:** `ReplayReport` carries `test_id`/`version`/`build_type`. `verify_reproducibility()` populates them and rejects runner results that don't match the requested context; the classifier rejects mismatched provenance outright and treats missing provenance conservatively (never confirms, never inferred); the regression generator requires it in bundle metadata and checks it against the bundle's crash version and build type.
- **Execution-context enforcement everywhere:** the shared `assert_execution_context()` rule is applied by replay verification, every minimization run (`CrashSignaturePredicate`, including final revalidation and lax mode — and any version/build/test change from the original signature is refused outright; there is no override escape hatch: to minimize another context, obtain a real `ExecutionResult` from it and construct a new predicate), and regression verification (returned version/build_type must match the requested run; both expectations must carry an expected `test_id` — promotion persists bundle replay provenance into new manifest entries, and legacy entries without it are rejected before any execution, never inferred from results). Violations raise, never `ok=True`.
- **CLI and reporter output guards:** `validate` rejects `--output-json`/`--output-md` that alias the input config (exit 30, nothing written); `report` keeps its `--results` protection; `write_reports()` itself rejects JSON/Markdown outputs that alias each other, including hard links and symlinks, before writing either file. All guards share the `paths_alias()` helper in the neutral `src/paths.py` module (`samefile()` plus a normalized absolute-path fallback).
- **Strict expectation validation:** regression expectations reject non-boolean `crash`, boolean/string `exit_code` values, missing required fields, unsupported manifest formats, and malformed entries — nothing is coerced, and rejections happen before any runner call or suite write. This applies to promotion, manifest deserialization, *and* the public `verify_regression()` API itself (both expectations are validated before the first execution). Supplied signatures must be real `CrashSignature` objects in the Python API (no implicit dict/list/string conversion; only manifest deserialization converts JSON structures explicitly).
- **Full RELRO recognition:** immediate binding is detected via `DT_BIND_NOW`, `DF_1_NOW` in `DT_FLAGS_1`, *and* `DF_BIND_NOW` in `DT_FLAGS` (pyelftools and readelf paths).
- **ddmin empty input:** after the chunk loop the empty input is tested once, so a one-byte input can still reduce to empty (skipped when the iteration budget is exhausted).

## Documentation

Project planning documents live in [`docs/`](docs/):

| Document | Description |
| --- | --- |
| [Project 1 Specification](<docs/پروژه ۱ - صورت پروژه (Project 1 Specification).pdf>) | Official project statement (Persian) |
| [Easy-Language Explanation of Project 1](<docs/01 - Easy-Language Explanation of Project 1.docx>) | Plain-language walkthrough of the project goals |
| [4-Person Task Breakdown, Structure & Deliverables](<docs/02 - 4-Person Task Breakdown, Structure & Deliverables.docx>) | Per-member task split, structure, and deliverables |
| [Overall Architecture, Timeline & Task Dependencies](<docs/03 - Overall Architecture, Timeline & Task Dependencies.docx>) | Architecture overview, schedule, and task dependencies |
| [Person 3 Development Plan](<docs/04 - Person 3 Development Plan.md>) | Build plan for the Reproducibility, Minimizer & Binary Hardening modules |
| [Validation Pipeline](<docs/09 - Validation Pipeline.md>) | End-to-end validate pipeline: setup, schema, targets, scenario matrix, limitations |
| [Final Report](<docs/10 - Final Report.md>) | Consolidated course-upload report: architecture, verification evidence, defense mapping |
| [Team Contributions](<docs/11 - Team Contributions.md>) | Verifiable module ownership vs. personal contribution claims (requires team confirmation) |

## Validation pipeline

`validate` executes the real pipeline — config → isolated builds → hardening → source analysis → execution → oracle → replay/minimize/bundle → correlate/classify → regression verification → reports → exit gate:

```bash
docker build -t patchguard-sandbox:latest .   # once; network needed
./targets/build_fixture_target.sh             # deterministic C fixture target
PYTHONPATH=src .venv/bin/python -m patch_validator validate \
  --config targets/configs/scenario-correct.yaml \
  --base any --patched any \
  --output-json /tmp/pg-out/report.json --output-md /tmp/pg-out/SUMMARY.md
./run_all_scenarios.sh                        # asserts 0 / 10 / 20 / 40 / 30
```

The scenario matrix is verified with real Docker execution: correct→0, incomplete→10, regression→20, no-bug→40, build-fail→30. The cJSON open-source target (CVE-2023-53154, pinned commits) is prepared; its scenario runs require authorization to execute the externally cloned code (see [docs/09](<docs/09 - Validation Pipeline.md>)).

The GitHub Actions workflow runs module tests, real container/cross-module integration tests, and the full scenario matrix — Docker prerequisites fail the required jobs rather than skipping their essential checks.

## Person 4: reporting and CI

Generate reports from classified upstream JSON results:

```bash
PYTHONPATH=src .venv/bin/python -m patch_validator report \
  --results examples/classified_results.json \
  --output-json /tmp/patchguard-report/report.json \
  --output-md /tmp/patchguard-report/SUMMARY.md
```

The gate uses `30 > 10 > 20 > 40 > 0`; missing completion evidence cannot pass.
JSON retains all supplied findings, traces, correlations, and artifacts; Markdown
summarizes findings, release/sanitized runs, reproducers, and binary hardening.

See [Person 4 reporting contract and remaining work](<docs/05 - Person 4 Reporting and Integration.md>).

## Person 2: patch analysis and verdicts

Requires `clang` on PATH (in addition to GCC/binutils used by the tests).

- `src/diff_parser/diff_analyzer.py`: Git hunks, Clang C/C++ function spans, direct caller/callee graph.
- `src/correlator/correlator.py`: stack/coverage evidence linking to changed code.
- `src/oracle/functional_oracle.py`: independent JSON reference expectations.
- `src/classifier/verdict.py`: five-state per-finding verdicts; output fits the existing reporter.

No target-specific names are hardcoded. Missing evidence stays Inconclusive;
release and sanitized executions are kept separate. The runner adapter is available; coverage integration
and full `validate` orchestration remain pending.

See [Person 2 APIs, oracle schema, and limitations](<docs/06 - Person 2 Analysis and Verdict.md>).

Source call-graph edges preserve Clang symbol identity and linkage: a static
function in another translation unit cannot satisfy an external call with the
same name. ELF inspection reads runtime tags from `PT_DYNAMIC`, including when
section headers are absent; dynamic symbol/relocation evidence also preserves
canary detection in the sectionless test fixtures.

## Person 1: build and execution integration

The `sahand` implementation is integrated through canonical shared models and
`runner.adapter.TargetRunnerAdapter`, which connects its Docker sandbox to the
existing replay, minimization, and regression APIs. YAML configs require PyYAML
(included in `requirements.txt`). Build the image with:

```bash
docker build -t patchguard-sandbox:latest .
```

See [Person 1 integration and runner usage](<docs/08 - Person 1 Integration.md>)
for the reconciled contracts, input semantics, test coverage, and remaining
pipeline work. Container tests require Docker access and this image; skipped
container tests do not establish production sandbox correctness.
