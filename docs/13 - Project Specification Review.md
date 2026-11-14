# Project specification review

Reviewed on 14 November 2026 against commit `cb8aefa` and the official Project 1 specification in this repository. The local README edit and untracked research documents were preserved. This is a review report; application code was not changed.

**Verdict: request changes before claiming full compliance.** The integrated pipeline works for the supplied targets and the existing test suite passes, but additional probes demonstrate defects in source-path safety, PASS gating, generated regression verification, and execution evidence.

## Remediation after the review

The ten blocking findings R1–R10 below have been addressed. Source/work/output overlaps are rejected, clean regressions retain independent output oracles, mandatory coverage gates PASS, configured analysis flags reach Clang, replay preserves timeouts and pinned Docker execution settings, Docker infrastructure failures become setup errors, canary diagnostics use GDB frames, ASan address classification is conservative, and generated suites persist across CI runs.

Verification after remediation: **462 passed, zero failed, zero skipped** in 185.69 seconds, plus **8/8 validation scenarios passed**. Added checks include held-out safe and regressing patches, suite reuse in a fresh workspace, and relocated Docker reproducers in stdin/file/args modes. These results supersede the baseline verdict for R1–R10; the original findings below remain as historical evidence. The nonblocking limitations and human submission/defense requirements still apply. The updated packaging script was syntax-checked; the delivery archive was not regenerated during this verification.

## Baseline verification

- Executed the committed source in an isolated copy at `/tmp/patchguard-review-vjlF80`; the project's target repositories and existing outputs were not rebuilt or overwritten.
- Full suite: **437 passed, zero failed, zero skipped**, in 140.09 seconds. This includes real Docker tests and GDB-backed local integration tests. JUnit evidence: [review test results](/home/aida/Uni/Security/Project/patchguard/artifacts/review-cb8aefa/tests.xml).
- Ran three additional review probes with compiled C fixtures: removing every boundary test still produces PASS; required compiler defines reach all four builds but not AST analysis; configured replay timeout is not forwarded to the bundler. All three reproduced the suspected behavior.
- Additional disposable probes confirmed destructive checkout-path overlap, regression verification accepting wrong output, loss of supplied GDB frames for canary failures, non-null ASan SEGV misclassification, and Docker-daemon failure being returned as ordinary target output.
- Checked the four shell scripts with `bash -n`.
- Inspected both delivered Git bundles: each contains the required main/correct/incomplete/regression branches. The earlier relative bundle-output-path defect is fixed in the reviewed commit.
- Fresh eight-scenario Docker matrix: **8/8 passed**, with results below. Only the hardcoded report directory was redirected in the temporary runner to avoid overwriting previous project reports; scenario logic and production source were unchanged. Copies of the eight reports are under [review artifacts](/home/aida/Uni/Security/Project/patchguard/artifacts/review-cb8aefa).

## Requirement comparison

The section numbers below follow the official Persian PDF, rather than the internal development plan.

| Specification requirement | Current implementation | Assessment |
| --- | --- | --- |
| Section 2: Linux x86_64 ELF targets with source for both versions | Four builds, ELF inspection, configurable target repository and refs | Implemented for the supplied targets; path-safety defect R1 remains |
| Section 2: stdin, file, or argument input | Sandbox and adapter support all three modes; tests cover delivery contracts | Implemented |
| Section 2: adding a target through configuration | Build commands, refs, binary path, test inputs, oracle, limits | Partial: AST configuration is disconnected, R4; C++ naming limitation N1 |
| Section 2: independent functional reference | Exact, regex, JSON, stderr, and exit-code expectations with provenance | Implemented for original tests; generated tests lose output expectations, R2 |
| Section 3.1: source diff and evidence-based correlation | Git snapshots, Clang AST, direct calls, stack frames, confidence and conservative unknown status | Implemented for supplied cases; R4 and N1 limit generalization |
| Section 3.1: Fixed, Incomplete Fix, New Issue, Functional Regression, Inconclusive | Classifier and aggregate exit-code resolver | Implemented; R3 can incorrectly report overall completion |
| Section 3.2: valid, boundary, invalid tests on corresponding Release/Sanitized builds | All configured tests run on both versions and build types | Supplied scenarios meet this; missing categories are not enforced, R3 |
| Section 3.2: detailed error type, mechanism, termination and limits | Structured execution results and diagnostics parsing | Partial: R7, R8 and R9 |
| Section 3.3: at least three replays and flaky evidence | Default three replays, strict signatures, context checks, flaky fallback | Implemented; execution timeout differs between stages, R5 |
| Section 3.3: automatic minimization preserving the same error | ddmin, top-frame/error matching, final revalidation, original and minimized files | Implemented; execution-setting defect R5 remains |
| Section 3.3: reproducible bundle with versions, hashes, settings and invocation | Binary/input copies, metadata and reproduce.sh | Partial: effective environment and execution context are not recreated, R6 |
| Section 3.3: generated regressions run in later pipelines and verify correct behavior | Content-addressed manifests and reloading of saved suites | Partial: R2 and R10 |
| Section 3.4: NX, PIE, three-level RELRO, canary evidence, downgrade warnings and caveats | ELF inspector and before/after deltas | Implemented; no requirement that a warning alone force a particular exit code |
| Section 3.5: CLI, JSON, human summary, priority 30 > 10 > 20 > 40 > 0 | CLI, reporter, exit gate, three CI jobs | Implemented for normal paths; infrastructure errors are misrepresented in R7 |
| Section 4: two independent programs, at least one real project, four versions each | Custom C fixture and upstream cJSON; four branches in each | Implemented and present in delivered Git bundles |
| Section 4: unseen patches and no filename-based verdict | Configurable refs, actual execution; no target/scenario-name decision branches found in src | Architecture supports new refs; R4 and N1 are demonstrated generalization risks |
| Section 5: source, target versions, tests, bundles, reports, pipeline and independent setup | Repository, README, scripts, delivery reports and Git bundles | Largely implemented; R6 and R10 weaken independent evidence delivery |
| Sections 2/4: instructor approval of targets and independent reference | Provenance strings and target documentation | Approval cannot be established from code or the reviewed artifacts |
| Section 6.2: individual contributions and live defense | Named contributions and module mapping documented | Documented claims; individual understanding and contribution verification require the defense process |

## Blocking findings

These are blockers to a claim of full compliance. P1 findings can cause data loss or an unjustified success result. P2 findings affect required evidence, generalization, or CI behavior.

### R1 P1 A permitted work directory can erase the target repository

**Location:** [builder.py:79](/home/aida/Uni/Security/Project/patchguard/src/builder/builder.py:79), [loader.py:213](/home/aida/Uni/Security/Project/patchguard/src/config/loader.py:213).

The loader rejects a work directory inside the source repository, but accepts a work directory that contains the repository. The builder deletes fixed checkout destinations before checking whether they overlap the source. For `repo_path=/tmp/example/src_base` and `work_dir=/tmp/example`, preparing the base checkout deletes the original repository and its `.git` history.

**Evidence:** reproduced in a disposable Git repository with valid `main` and `correct` refs. Configuration loaded successfully; both the original C file and Git history disappeared after `_prepare_checkouts`.

**Required correction:** validate every checkout/build destination against the source repository and other protected paths before any `rmtree`. Perform the same guard inside the public builder API, not only the config loader. Ref resolution must not require destructive preparation first.

### R2 P1 Generated regressions can accept incorrect program output

**Requirement:** sections 2 and 3.3 require expected output/behavior, including on the minimized regression input.

**Location:** [generator.py:33](/home/aida/Uni/Security/Project/patchguard/src/regression_gen/generator.py:33), [generator.py:448](/home/aida/Uni/Security/Project/patchguard/src/regression_gen/generator.py:448).

`VersionExpectation` cannot store stdout/stderr oracle expectations. Its clean-run evaluation accepts the expected exit code without checking output. The independent oracle on the original configured input does not cover a different minimized input.

**Evidence:** an execution with deliberately wrong stdout and stderr was accepted by the saved-regression evaluator when its exit code matched.

**Required correction:** persist the independent oracle appropriate to each generated input and evaluate it during promotion and every later verification. If minimization changes the input's intended semantics, derive an independent expectation or report the missing expectation; do not infer correctness from the patched program's output.

### R3 P1 PASS does not require the mandatory test categories

**Requirement:** sections 3.2 and 3.5 require valid, boundary and invalid tests, with mandatory checks complete before PASS.

**Location:** [loader.py:185](/home/aida/Uni/Security/Project/patchguard/src/config/loader.py:185), [validation.py:302](/home/aida/Uni/Security/Project/patchguard/src/validation.py:302).

The loader only requires a nonempty test list. The final completion flag checks evidence gaps and saved regressions, without requiring boundary coverage or verifying the full required input-category coverage.

**Evidence:** a real local pipeline run with every boundary test removed returned `exit_code=0` and `mandatory_checks_complete=True`.

**Required correction:** validate required test categories and valid/invalid coverage before execution, track their completed executions, and refuse PASS when a mandatory category is absent.

### R4 P2 Build configuration never reaches source analysis

**Requirement:** sections 2 and 4 require configuration-based target onboarding and evaluation of unseen patches within the supported scope.

**Location:** [validation.py:157](/home/aida/Uni/Security/Project/patchguard/src/validation.py:157), [diff_analyzer.py:365](/home/aida/Uni/Security/Project/patchguard/src/diff_parser/diff_analyzer.py:365).

The analyzer accepts compile arguments, but the pipeline passes none and the validation schema exposes no analyzer arguments. Include paths, defines and language settings used by a target build cannot be supplied to the integrated AST stage. Generated headers are also not taken from the build environment.

**Evidence:** added a required `REVIEW_FLAG` macro to both revisions and supplied it in both build commands. All four binaries built successfully; validation then returned 30 because Clang did not receive the macro.

**Required correction:** pass explicit per-target analysis arguments or a compilation database into the analyzer, using the appropriate version's headers/build environment. Add an end-to-end onboarding test requiring a define and an include directory.

### R5 P2 Replay and minimization silently use different time limits

**Requirement:** sections 3.2 and 3.3 require corresponding settings and reproducible evidence.

**Location:** [validation.py:346](/home/aida/Uni/Security/Project/patchguard/src/validation.py:346).

The initial replay receives `cfg.target.timeout_sec`. `build_reproducer` is then called without that value, so its additional replay and ddmin execution use the default five seconds. A configured three-second run and its generated bundle therefore do not have identical execution limits.

**Evidence:** a call-capture probe with timeout 0.25 recorded 0.25 for the initial replay and no timeout argument for the bundler, whose default is 5.0.

**Required correction:** forward the configured timeout and centralize execution settings across execution, replay, minimization and saved-regression verification.

### R6 P2 Standalone replay does not recreate the original execution context

**Requirement:** sections 3.3 and 5 require effective build/environment settings and independently reproducible execution evidence; tests must use an isolated environment.

**Location:** [bundler.py:296](/home/aida/Uni/Security/Project/patchguard/src/reproducer/bundler.py:296), [bundler.py:341](/home/aida/Uni/Security/Project/patchguard/src/reproducer/bundler.py:341).

Generated scripts execute the copied binary directly on the host. Metadata records user-configured environment variables, but not the image's effective sanitizer defaults, an image digest, or execution resource limits. Shared-library names are listed but not supplied. The copied binary may need runtime libraries absent from another host. The recorded compile_flags are generic build-type flags rather than the complete effective build command.

**Evidence:** code and generated-artifact inspection; no separate incompatible-host replay was performed. Dockerfile defaults include sanitizer settings not automatically reproduced by a bundle whose configured environment is empty.

**Required correction:** provide an isolated replay command using the recorded image/environment and limits, retain complete build settings, and verify bundle relocation/replay in a clean execution environment. Keep any host-only replay explicitly documented as an alternative with prerequisites.

### R7 P2 Docker launch failures are treated as target outcomes

**Requirement:** section 3.5 assigns infrastructure failures code 30 and distinguishes them from target failures and inconclusive security evidence.

**Location:** [sandbox.py:227](/home/aida/Uni/Security/Project/patchguard/src/runner/sandbox.py:227).

The runner copies the Docker CLI exit code into a normal target result without establishing that a container started. A daemon/launch failure is then processed by the oracle and classifier, rather than raised as a configuration/infrastructure error. It can become an oracle mismatch, inconclusive result, or apparent functional regression instead of code 30.

**Evidence:** a disposable Docker-command stub returning 125 with `Cannot connect to the Docker daemon` produced an ordinary execution result with `exit_code=125`, `detection_mechanism=NONE`, and `crashed=False`.

**Required correction:** distinguish Docker launch/transport failure from the actual container process exit, preserve engine diagnostics, and raise `ConfigOrBuildError` for infrastructure failures. Do not blindly reserve a numeric exit code that the target itself could legitimately return; inspect launch/container state.

### R8 P2 Canary diagnostics discard available GDB evidence

**Requirement:** sections 3.1 and 3.2 require detailed diagnostics and a usable link between a finding and the patch.

**Location:** [parser.py:140](/home/aida/Uni/Security/Project/patchguard/src/diagnostics/parser.py:140).

When stack-smashing text is detected, the parser returns immediately using only sanitizer-format frames from the message. The supplied `gdb_backtrace` is ignored. Ordinary canary failures do not contain sanitizer-format frames, so evidence is lost even if the runner collected a usable backtrace. Replay/minimization and correlation then become inconclusive.

**Evidence:** passing a stack-smashing message together with a GDB `main` frame yielded `stack-canary-abort` with an empty stack.

**Required correction:** preserve the BINARY_PROTECTION mechanism while falling back to the collected GDB frames when sanitizer frames are absent. Add a parser/integration test for this combination.

### R9 P2 Non-null ASan segmentation faults are mislabeled as null dereferences

**Requirement:** section 3.2 requires accurate error categorization without claiming an unsupported root cause.

**Location:** [parser.py:205](/home/aida/Uni/Security/Project/patchguard/src/diagnostics/parser.py:205).

Every ASan error type beginning with `segv` is rewritten to `null-dereference`. This applies even when the reported address is non-null. A specific earlier null-address matcher already exists, making the broad fallback unnecessary and inaccurate.

**Evidence:** an ASan diagnostic reporting SEGV at `0x41414141` was categorized as `null-dereference`.

**Required correction:** use null-dereference only with supporting address/UBSan evidence; retain a generic invalid-access/SEGV category when the precise cause is unknown.

### R10 P2 Generated regression suites do not survive fresh CI runs

**Requirement:** section 3.3 requires generated regressions to be checked in subsequent pipeline runs.

**Location:** [patch_validation.yml:72](/home/aida/Uni/Security/Project/patchguard/.github/workflows/patch_validation.yml:72), [validation.py:164](/home/aida/Uni/Security/Project/patchguard/src/validation.py:164).

Local saved-suite re-verification exists and is tested. However, the CI artifact step only uploads `/tmp/patchguard-scenarios/`, containing reports and stdout logs. The generated suites and reproducer bundles are under the repository's ignored `outputs/` directory. There is no checked-in suite or restore step for the next fresh runner. Thus later CI runs cannot reload the previously generated cases.

**Evidence:** workflow, scenario-runner and suite-loading path inspection. No historical GitHub workflow execution was queried in this review.

**Required correction:** choose an explicit persistence mechanism for approved generated regression cases, restore those cases before validation, and upload bundles/suites with the reports. Verify persistence across two fresh workspaces, rather than only two invocations sharing one local output directory.

## Non-blocking findings and limitations

### N1 C++ symbol matching and cross-version source identities remain limited

[correlator.py:70](/home/aida/Uni/Security/Project/patchguard/src/correlator/correlator.py:70) compares the AST's unqualified function name directly with the diagnostic function name. A probe with AST function `parse` and an ASan frame `N::parse(int)` returned INCONCLUSIVE despite a changed function and matching source line. Symbol identity exists in the static call graph, but not in this frame matcher. Separately, [models.py:146](/home/aida/Uni/Security/Project/patchguard/src/models.py:146) requires equal available file/line locations, which can reject equivalence across shifted source lines or different absolute build roots.

These conservative results do not create a false PASS, and the supplied targets are C. They are limitations to disclose before claiming broad C++ or unseen-patch support. Preserve full qualified/symbol identities and use a source-coordinate mapper where equivalence is established; do not simply weaken crash matching.

### N2 Report publication is not atomic and routine oracle results are not retained

[report_gen.py:159](/home/aida/Uni/Security/Project/patchguard/src/reporter/report_gen.py:159) writes the two final files sequentially in place. A failed second write can leave a mixed report pair. Also, [validation.py:204](/home/aida/Uni/Security/Project/patchguard/src/validation.py:204) computes oracle results for every execution but retains them in findings only for interesting cases; normal passing test expectations/reasons are absent from the JSON. Atomic publication and a complete per-execution oracle table would improve auditability. Neither is treated here as an explicit requirement for a particular storage mechanism.

### N3 Documentation and evidence versions should be reconciled

[docs/09:30](</home/aida/Uni/Security/Project/patchguard/docs/09 - Validation Pipeline.md:30>) says the CLI refs are compatibility flags, although the same document later correctly describes them as overrides. [docs/10:93](</home/aida/Uni/Security/Project/patchguard/docs/10 - Final Report.md:93>) records 435 tests, while the current verified suite has 437. The older workspace XML records 427. Preserve old results as historical evidence and label them with their commit/run, rather than presenting all counts as the same final state.

## Evidence requiring team confirmation

- Instructor approval of the chosen targets, reference tests and expected behavior, as required by sections 2 and 4, is not established by a provenance string.
- The contribution document now names members and describes their roles; this is present and should not be reported as an empty contribution form. The review cannot independently authenticate authorship or individual understanding.
- No explicit two-held-out-patch rehearsal record was found in the reviewed delivery evidence. The official requirement is successful live unseen-patch evaluation; the rehearsal is preparation, not a separate mandated discovery task.
- Automatic fuzzing, discovery of a new vulnerability, and automatic coverage collection are not mandatory in the official document. Known public vulnerabilities and manually designed bypass inputs are permitted. Stack/call-graph evidence can satisfy correlation without coverage.
- Synthetic incomplete/regression variants are valid scenario fixtures; their origin is documented. Only one of the two targets must be a real project, which cJSON satisfies.

## Recommended implementation order

1. Prevent destructive source/workspace overlap (R1).
2. Close unjustified verification/PASS paths (R2, R3).
3. Make target onboarding and infrastructure outcomes reliable (R4, R7).
4. Unify replay context and preserve diagnostics (R5, R6, R8, R9).
5. Persist generated regression evidence between CI runs (R10).
6. Re-run the existing suite, the targeted counterexamples and the eight scenarios; then update the final report and rehearse an unseen patch.

## Fresh scenario results

| Scenario | Expected exit | Observed exit |
| --- | --- | --- |
| scenario-correct | 0 | 0 |
| scenario-incomplete | 10 | 10 |
| scenario-regression | 20 | 20 |
| scenario-no-bug | 40 | 40 |
| scenario-build-fail | 30 | 30 |
| scenario-cjson-correct | 0 | 0 |
| scenario-cjson-incomplete | 10 | 10 |
| scenario-cjson-regression | 20 | 20 |

The original test suite and these supplied scenarios do not include the counterexamples described in R1-R10. Their success does not negate those independently reproduced gaps.
