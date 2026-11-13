# Validation pipeline

`python -m patch_validator validate` now runs the real pipeline: configuration → isolated builds → hardening inspection → source analysis → dynamic execution → independent oracle → replay/minimization/reproducer bundles → correlation/classification → regression promotion/verification → reports → aggregate exit code.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
docker build -t patchguard-sandbox:latest .   # network needed once
./targets/build_fixture_target.sh             # deterministic C fixture target
PYTHONPATH=src .venv/bin/python -m pytest -q  # includes real Docker tests
./run_all_scenarios.sh                        # full scenario matrix
```

`RUN_CJSON=0 ./run_all_scenarios.sh` skips the open-source target scenarios.

## Working validate commands

```bash
PYTHONPATH=src .venv/bin/python -m patch_validator validate \
  --config targets/configs/scenario-correct.yaml \
  --base <any> --patched <any> \
  --output-json /tmp/pg-out/report.json --output-md /tmp/pg-out/SUMMARY.md
```

`--base`/`--patched` are accepted for CLI compatibility; the refs come from the config file.

## Configuration schema

`targets/configs/scenario-correct.yaml` is the reference. Fields:

| Field | Meaning |
| --- | --- |
| `target_name`, `repo_path`, `base_ref`, `patched_ref` | target identity; refs must exist in `repo_path` (a git repo) |
| `build_cmd_release`, `build_cmd_sanitized` | shell commands run inside the sandbox image with `CFLAGS/CXXFLAGS/LDFLAGS` exported (`-O2` / ASan+UBSan) |
| `binary_rel_path` | produced ELF, relative to the build dir |
| `input_mode` | `stdin` / `file` / `args` |
| `argv_template` | optional; exactly one `{input}` placeholder for file/args modes, none for stdin |
| `timeout_sec`, `memory_mb`, `cpus`, `env_vars` | resource limits and recorded environment |
| `oracle_source` | required provenance record of where expected behavior comes from |
| `work_dir`, `output_dir` | build artifacts and reports/reproducers/regression suite; must not live inside the target repo |
| `tests` | see below |

Relative paths in the config resolve against the invocation working directory.

Each test: `id` (unique), `kind` (`functional`/`boundary`/`security`), `input` (string) or `input_hex`, `expected_exit_code` (integer or null), `is_valid_input`, `stdout_kind` (`exact`/`regex`/`json`/`none`), `stdout_value`, `stderr_pattern`. Security tests require explicit `base_expect`/`patched_expect` (`{crash: bool, exit_code?: int}`), which also drive regression promotion. Rejections happen before any build or execution: malformed types, duplicate test IDs, invalid templates, unsafe output/input collisions, missing files.

## Targets and provenance

**fixture-target** (deterministic C parser, args mode, MIT-style course fixture): four patch scenarios + a no-bug scenario, built by `targets/build_fixture_target.sh`.

**cjson-target** (real open-source target): [cJSON](https://github.com/DaveGamble/cJSON), MIT license. CVE-2023-53154 — heap-based buffer over-read in `parse_object` on trailing-comma input such as `{"1":1,` (CWE-125, [NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-53154), upstream [issue #800](https://github.com/DaveGamble/cJSON/issues/800), fix commit `3ef4e4e730e5efd381be612df41e1ff3f5bb3c32` "Fix heap buffer overflow", released in 1.7.18).

- Vulnerable: the fix commit's parent `826cd6f842ae7e46ee38bbc097f9a34f2947388d` ("Add test for heap buffer overflow") — vulnerable, pre-1.7.18; v1.7.17 (`87d8f09`) is the last tagged vulnerable release. Pinning the parent keeps the scenario diff exactly the fix.
- Correct: the upstream fix commit + harness.
- Incomplete: synthetic patch protecting only the first trailing comma — `{"1":1,` is rejected, `{"1":1,"2":2,` still over-reads.
- Regression: synthetic over-strict patch (real fix + reject any multi-member object), breaking valid `{"a":1,"b":[2,3]}` input.
- Harness: a stdin driver that feeds `cJSON_ParseWithLength` an **exactly-sized** `malloc` buffer — cJSON uses the caller's buffer directly, so only exact sizing exposes the 1-byte over-read to ASan (verified: `heap-buffer-overflow` under ASan on the pinned vulnerable commit; clean `parse error` after the fix).

Reproduce: `./targets/build_cjson_target.sh && docker build -t patchguard-sandbox:latest . && PYTHONPATH=src .venv/bin/python -m patch_validator validate --config targets/configs/scenario-cjson-correct.yaml ...` (executes upstream code only inside the isolated sandbox).

## Scenario matrix

| Scenario | Expected exit | Observed |
| --- | --- | --- |
| `scenario-correct` | 0 | 0 |
| `scenario-incomplete` | 10 | 10 |
| `scenario-regression` | 20 | 20 |
| `scenario-no-bug` | 40 | 40 |
| `scenario-build-fail` | 30 | 30 |
| `scenario-cjson-correct` | 0 | 0 |
| `scenario-cjson-incomplete` | 10 | 10 |
| `scenario-cjson-regression` | 20 | 20 |

Exit precedence is `30 > 10 > 20 > 40 > 0`; partial evidence is retained in the report when a pipeline stage fails. Completion flags are derived from work actually performed.

## Limitations and TA coordination

- The fixture oracle expectations are team-designed illustrations; they require TA approval as an independent reference, as do the cJSON harness expectations (upstream parser behavior for valid/rejected JSON, verified against the pinned commits).
- The cJSON scenarios were executed with real Docker isolation against the pinned commits: the correct scenario reproduces the over-read on the vulnerable ref and verifies the upstream fix (exit 0); the incomplete scenario's bypass input still crashes the synthetic partial patch (exit 10); the regression patch breaks valid multi-member JSON (exit 20). Incomplete/regression branches for cJSON are synthetic, not upstream commits.
- cJSON's release-build over-read may not crash visibly; the finding is expected to surface in the sanitized build only. Incomplete/regression branches for cJSON are synthetic, not upstream commits.
- The pipeline runs one scenario per invocation; concurrent runs sharing an `output_dir` are not supported.
- `--base`/`--patched` CLI flags are vestigial (refs come from the config).
