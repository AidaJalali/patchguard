# Team Contributions

This record accompanies the final delivery. It separates **verifiable evidence** (files, modules, documentation, git history) from **personal contribution claims**, which each member must confirm. Planned roles from `docs/02` and module ownership are listed only as context, not as proof of actual work.

| Member | Role (docs/02) | Verifiable evidence in the repository | Design / implementation / testing / results analysis / documentation — requires team confirmation |
| --- | --- | --- | --- |
| Person 1 — build & execution lead | Containerized build, dual Release/Sanitized builds, Docker sandbox, crash diagnostics | `Dockerfile`; `src/builder/builder.py`; `src/runner/sandbox.py`; `src/runner/adapter.py`; `src/diagnostics/parser.py`; `src/config/loader.py`; `src/exceptions.py`; `tests/test_person1.py`, `tests/test_person1_integration.py`; `docs/08 - Person 1 Integration.md`; git history: the `sahand` integration commits (author `shndap`, merged in `bac9501`) | ▢ |
| Person 2 — analysis & verdict lead | Git diff + Clang function spans, correlation, independent oracle, 5-state classifier | `src/diff_parser/diff_analyzer.py`; `src/correlator/correlator.py`; `src/oracle/functional_oracle.py`; `src/classifier/verdict.py`; `tests/test_person2.py`; `docs/06 - Person 2 Analysis and Verdict.md` | ▢ |
| Person 3 — reproducibility & hardening lead | Replay verification, ddmin minimization, reproducer bundles, regression generation/verification, ELF hardening | `src/reproducer/bundler.py`; `src/minimizer/ddmin.py`; `src/regression_gen/generator.py`; `src/hardening/elf_checker.py`; `src/models.py` (shared contracts); `tests/test_bundler.py`, `tests/test_ddmin.py`, `tests/test_regression_gen.py`, `tests/test_elf_checker.py`; `docs/04 - Person 3 Development Plan.md` | ▢ |
| Person 4 — reporting & CI lead | CLI, exit-code resolver, JSON/Markdown reports, CI workflow, target curation | `src/cli.py`; `src/orchestrator.py`; `src/reporter/report_gen.py`; `src/patch_validator/`; `.github/workflows/patch_validation.yml`; `tests/test_reporting.py`; `docs/05 - Person 4 Reporting and Integration.md` | ▢ |
| Pipeline integration | End-to-end `validate` orchestration, validation config schema, target construction scripts, scenario matrix | `src/validation.py`; `tests/test_validation.py`; `targets/build_fixture_target.sh`; `targets/build_cjson_target.sh`; `run_all_scenarios.sh`; `docs/09`, `docs/10`; git history: commits by `Aida Jalali` | Requires team confirmation |

Known limitations of this record:

- Git author names do not identify the four members: most commits are merged under the repository owner's identity, and `shndap` is the only distinct author. Commit counts are therefore not used as ownership evidence.
- The pipeline-integration row reflects work performed across the repository's later history; which members performed which parts requires team confirmation.
- Fill each ▢ with the member's own statement (design, implementation, testing, results analysis, documentation) before submission.
