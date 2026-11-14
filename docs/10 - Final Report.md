# Patchguard — Final Report

Automated security patch validation and regression testing for C/C++ applications in CI/CD pipelines.

Course: Data and Network Security (امنیت داده و شبکه) — Sharif University of Technology
Team: 4 members · Project 1 · Weight 2.5/20

---

## 1. What the tool does

Given a C/C++ target repository, a vulnerable base revision, and a patched revision, `patchguard` compiles both versions twice (Release and ASan/UBSan-sanitized) inside an isolated Docker sandbox, executes functional, boundary, and security test inputs against all four binaries, and decides automatically whether the patch is safe to merge:

- **Fixed** (exit 0) — base crash reproduced and confirmed, patched satisfies the independent oracle.
- **Incomplete Fix** (exit 10) — a variant input still triggers the vulnerability on the patched version.
- **Functional Regression** (exit 20) — valid inputs that passed on base now fail on patched.
- **Inconclusive** (exit 40) — missing/flaky evidence, unproven correlation, or incomplete mandatory checks.
- **Build/Config/Infrastructure error** (exit 30).

The verdict is derived only from executed evidence: strict crash-signature equivalence, replay determinism, patch correlation, an independent functional oracle, and binary hardening diffs — never from static text inspection or the patched output itself.

## 2. Architecture

Seven stages, wired by `src/validation.py` and the `validate` CLI:

| Stage | Owner | Modules |
| --- | --- | --- |
| Config & validation | Person 1 + pipeline | `src/config/loader.py` (YAML/JSON schema, strict pre-build validation) |
| Isolated dual builds | Person 1 | `src/builder/builder.py` — 4 binaries in the `patchguard-sandbox` Docker image |
| Binary hardening | Person 3 | `src/hardening/elf_checker.py` — NX/PIE/RELRO/Canary + downgrade detection |
| Diff & call-graph analysis | Person 2 | `src/diff_parser/diff_analyzer.py` (Clang AST, git hunks, insertion-point mapping) |
| Dynamic execution | Person 1 + 3 | `src/runner/sandbox.py`, `runner/adapter.py`, `src/diagnostics/parser.py` (ASan/UBSan/gdb) |
| Oracle & classification | Person 2 | `src/oracle/functional_oracle.py`, `src/correlator/correlator.py`, `src/classifier/verdict.py` |
| Reproducibility & regression | Person 3 | `src/reproducer/bundler.py` (3× replay + bundles), `src/minimizer/ddmin.py`, `src/regression_gen/generator.py` |
| Reports & exit gate | Person 4 | `src/orchestrator.py`, `src/reporter/report_gen.py`, `src/cli.py` |

Hard invariants enforced throughout: execution provenance (`test_id`/`version`/`build_type`) is validated on every result; Release and Sanitized evidence are never mixed; a timeout/OOM is never crash evidence; missing diagnostics can never confirm a finding; failed regression verification or any evidence gap blocks a PASS.

## 3. Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt      # pyelftools, pytest, pyyaml
docker build -t patchguard-sandbox:latest .    # network needed once
./targets/build_fixture_target.sh              # deterministic C fixture target
./targets/build_cjson_target.sh                # real open-source target (network needed)
.venv/bin/python -m pytest -q                  # full suite, including real Docker tests
```

## 4. Running a validation

```bash
PYTHONPATH=src .venv/bin/python -m patch_validator validate \
  --config targets/configs/scenario-correct.yaml \
  --output-json /tmp/pg-out/report.json --output-md /tmp/pg-out/SUMMARY.md
```

`--base`/`--patched` optionally override the config's refs. The full configuration schema (target refs, build commands, input modes, resource limits, functional/boundary/security tests, oracle expectations, output directories) is documented in `docs/09 - Validation Pipeline.md`. Invalid configurations — malformed types, duplicate test IDs, unsafe templates, NaN/inf limits, invalid regexes, output/input collisions — are rejected before any build or execution.

```bash
./run_all_scenarios.sh    # executes the complete scenario matrix and asserts exit codes
```

## 5. Targets and provenance

**fixture-target** — a deterministic C parser (argv mode) with an unbounded `strcpy` into an 8-byte heap buffer. Four patch variants plus a no-bug scenario, all team-authored, built from `targets/build_fixture_target.sh`.

**cjson-target** — the real open-source target: [cJSON](https://github.com/DaveGamble/cJSON), MIT license.
- Vulnerability: **CVE-2023-53154** — heap-based buffer over-read in `parse_object` on trailing-comma input such as `{"1":1,` (CWE-125). References: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-53154), upstream [issue #800](https://github.com/DaveGamble/cJSON/issues/800).
- Vulnerable ref: `826cd6f842ae7e46ee38bbc097f9a34f2947388d` (the commit immediately before the fix; pre-1.7.18; v1.7.17 is the last tagged vulnerable release).
- Correct ref: `3ef4e4e730e5efd381be612df41e1ff3f5bb3c32` ("Fix heap buffer overflow", released in 1.7.18) — applied unchanged.
- Incomplete/regression refs: synthetic scenario patches crafted by the team on top of the vulnerable commit (protecting only the first trailing comma; and rejecting all multi-member objects).
- Harness: a stdin driver feeding `cJSON_ParseWithLength` an exactly-sized `malloc` buffer — cJSON parses the caller's buffer in place, so exact sizing is what exposes the 1-byte over-read to ASan. **Verified by execution**: `heap-buffer-overflow` under ASan on the vulnerable ref; clean `parse error` (exit 1) after the fix.
- All runs execute the upstream code only inside the isolated Docker sandbox (`--network none`, memory/CPU/pids limits).

## 6. Scenario matrix (verified)

| Scenario | Meaning | Expected | Observed (2 clean runs) |
| --- | --- | --- | --- |
| `scenario-correct` | complete bounds fix | 0 | 0, 0 |
| `scenario-incomplete` | bypass input still crashes patched | 10 | 10, 10 |
| `scenario-regression` | fix rejects valid inputs | 20 | 20, 20 |
| `scenario-no-bug` | base bug does not reproduce | 40 | 40, 40 |
| `scenario-build-fail` | build command broken | 30 | 30, 30 |
| `scenario-cjson-correct` | upstream fix for CVE-2023-53154 | 0 | 0, 0 |
| `scenario-cjson-incomplete` | synthetic partial fix, bypass crashes | 10 | 10, 10 |
| `scenario-cjson-regression` | synthetic over-strict fix breaks valid JSON | 20 | 20, 20 |

Each scenario was executed end-to-end through real Docker: four sandbox builds, 20 instrumented executions, crash replays, ddmin minimization, reproducer bundles, correlation, classification, regression promotion and re-verification, hardening diffs, and `report.json`/`SUMMARY.md`. Scenario artifacts (reports, bundles, regression suites) are under `/tmp/patchguard-scenarios/<scenario>/` and `outputs/<target>/<scenario>/`.

## 7. Test evidence

- Full suite: **462 passed, 0 failed, 0 skipped** (verified on 14 November 2026) — including the real Docker build/run tests, the cross-module round trip (compiled C fixtures, real git snapshots, production ASan diagnostics parser), and the saved-regression re-verification tests.
- Scenario matrix: 8/8 on two independent clean runs.
- CI: three GitHub Actions jobs — unit tests, Docker integration tests, and the full scenario matrix — with Docker prerequisites required (not silently skipped). The CI environment packages match the tests' requirements (`llvm-18-tools` included for ASan symbolization in the local-transport fixtures).

## 8. Individual defense mapping

| Person | Role | Defense focus |
| --- | --- | --- |
| 1 | Containerized build & dynamic execution | Dockerfile/sandbox, dual builds, diagnostics parser; live: add a sanitizer flag or change limits |
| 2 | Diff analysis & verdict engine | Clang function spans, correlation evidence, 5-state classifier; live: adjust correlation depth |
| 3 | Reproducibility, minimization & hardening | 3× replay bundles, ddmin signature equivalence, ELF checks; live: tighten the predicate or rebuild with `-fno-stack-protector` |
| 4 | Orchestration, reporting & targets | CLI, exit gate, JSON/Markdown reports, scenario matrix; live: onboard an unseen patch |

## 9. Limitations

- cJSON's over-read does not crash the Release build in practice; the finding legitimately surfaces in the sanitized build only.
- The incomplete/regression branches of both targets are synthetic scenario patches (the correct branches use the real fixes).
- The pipeline runs one scenario per invocation; concurrent writers sharing an `output_dir` are unsupported (atomic publication guarantees the manifest is never partial).
- CI execution depends on the next push; the workflow itself and its local equivalents are fully verified.
