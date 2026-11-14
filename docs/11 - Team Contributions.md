# Team Contributions

| Member | Role | Modules & evidence |
| --- | --- | --- |
| **Sahand Akramipour** (401110618) | Build & dynamic execution | `Dockerfile`, `src/builder/builder.py`, `src/runner/sandbox.py`, `src/runner/adapter.py`, `src/diagnostics/parser.py`, `src/config/loader.py`, `src/exceptions.py`; tests in `tests/test_person1.py`, `tests/test_person1_integration.py`; `docs/08`; git history: the `sahand` integration commits |
| **Alireza MalekHosseini** (401106566) | Diff analysis & verdicts | `src/diff_parser/diff_analyzer.py`, `src/correlator/correlator.py`, `src/oracle/functional_oracle.py`, `src/classifier/verdict.py`; `tests/test_person2.py`; `docs/06` |
| **Aida Jalali** (401170542) | Reproducibility, minimization & hardening | `src/reproducer/bundler.py`, `src/minimizer/ddmin.py`, `src/regression_gen/generator.py`, `src/hardening/elf_checker.py`, shared contracts in `src/models.py`; `tests/test_bundler.py`, `tests/test_ddmin.py`, `tests/test_regression_gen.py`, `tests/test_elf_checker.py`, `tests/test_models.py`; `docs/04` |
| **Dorsa Sharifi** (401170604) | Reporting, CI & target curation | `src/cli.py`, `src/orchestrator.py`, `src/reporter/report_gen.py`, `src/patch_validator/`; `.github/workflows/patch_validation.yml`; `tests/test_reporting.py`; `docs/05` |
| **Team (integration)** | End-to-end `validate` orchestration | `src/validation.py`, `src/paths.py`, `tests/test_validation.py`, `targets/build_fixture_target.sh`, `targets/build_cjson_target.sh`, `run_all_scenarios.sh`, `package_deliverables.sh`, `docs/09`, `docs/10`, `docs/11`; carried primarily by Aida Jalali's commits with review input from the whole team |

## Contributions per member

### Sahand Akramipour — build & dynamic execution
- **Design:** the dual-build matrix (base/patched × release/sanitized) and the isolated Docker sandbox design (network none, memory/CPU/pids limits, stdin/file/args input delivery, `{input}` argv templates); the YAML/JSON target-config schema.
- **Implementation:** `Dockerfile`, `builder`, `runner.sandbox`, `runner.adapter` (RunnerPort compatibility), `diagnostics.parser` (ASan/UBSan/gdb parsing into the shared `ExecutionResult`), `config.loader`.
- **Testing:** `tests/test_person1.py` (config, diagnostics, sandbox contracts) and `tests/test_person1_integration.py` (adapter routing, parser contracts, the cross-module round trip with real GCC builds).
- **Analysis:** the error-type taxonomy and signal normalization rules that the whole pipeline depends on.
- **Documentation:** `docs/08` (reconciled contracts, input semantics, runner usage).

### Alireza MalekHosseini — diff analysis & verdicts
- **Design:** Clang-based function-span extraction, the caller/callee graph with linkage identity, the multi-level correlation evidence rules (direct frame, stack frame, call graph, coverage), and the five-state classifier with its evidence gates.
- **Implementation:** `diff_parser`, `correlator`, `oracle`, `classifier`.
- **Testing:** `tests/test_person2.py` (real C ASTs, cross-file calls, git snapshots, all five statuses, oracle validation, report-gate integration).
- **Analysis:** the correlation-confidence rules that map crash evidence to patch changes, including the insertion-point mapping for pure-insertion fixes.
- **Documentation:** `docs/06`.

### Aida Jalali — reproducibility, minimization & hardening
- **Design:** the strict crash-signature equivalence rule (`strict_crash_match`), replay provenance binding, ddmin with signature-preserving minimization, crash-consistent reproducer bundles, content-addressed regression publication, and the ELF hardening checks with downgrade detection.
- **Implementation:** `reproducer.bundler`, `minimizer.ddmin`, `regression_gen.generator`, `hardening.elf_checker`, and the shared contracts in `models.py`.
- **Testing:** `tests/test_bundler.py`, `tests/test_ddmin.py`, `tests/test_regression_gen.py`, `tests/test_elf_checker.py`, `tests/test_models.py` (including compiled C fixtures and the real `reproduce.sh` execution tests).
- **Analysis:** the evidence-integrity rules applied during combined reviews (provenance enforcement, bundle binding, verification gating).
- **Documentation:** `docs/04` and the pipeline sections of `docs/09`/`docs/10`.

### Dorsa Sharifi — reporting, CI & target curation
- **Design:** the report schema (`report.json`/`SUMMARY.md`), the exit-code resolver with the `30 > 10 > 20 > 40 > 0` priority, the CLI surface, and the three-job CI layout.
- **Implementation:** `cli`, `orchestrator`, `reporter`, `patch_validator` package, GitHub Actions workflow.
- **Testing:** `tests/test_reporting.py` (gate codes, invalid inputs, output-path protections).
- **Analysis:** completion-flag semantics and the report validation rules.
- **Documentation:** `docs/05`.

### Team — integration
The end-to-end `validate` orchestration, the validation config schema extensions, the two-target construction scripts, the scenario matrix, the delivery packaging, and this audit's fixes (saved-regression re-verification, exact-version bundles, CI repairs). Commits are attributed to Aida Jalali's account; the division of integration work was reviewed by all members.

## Notes
- The Person 1–4 role split above accurately describes the work as implemented: each member's modules, tests, and documentation are present in the repository and map one-to-one.
- Git author names are not used as the sole ownership evidence; module, test, and documentation presence is.
