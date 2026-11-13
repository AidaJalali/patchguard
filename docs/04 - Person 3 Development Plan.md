# Person 3 — Development Plan
**Reproducibility, Minimizer & Binary Hardening Lead**

Course: Data and Network Security — Sharif University of Technology · Deadline: 23 Aban 1405 (Nov 14, 2026)
Companion docs: [01 - Easy-Language Explanation](<01 - Easy-Language Explanation of Project 1.docx>) · [02 - Task Breakdown](<02 - 4-Person Task Breakdown, Structure & Deliverables.docx>) · [03 - Architecture & Dependencies](<03 - Overall Architecture, Timeline & Task Dependencies.docx>)

---

## 1. Scope & Rubric Mapping

Owned modules (20 rubric points — Capability 3 [15 pts] + Capability 4 [5 pts]):

| Task | Module | Rubric | Dependencies | Can start |
| --- | --- | --- | --- | --- |
| T3.4 | `src/hardening/elf_checker.py` | Capability 4 (5 pts) | **None** — works on any ELF | ✅ Day 1 |
| T3.2 | `src/minimizer/ddmin.py` | Capability 3 — minimization | Runner interface (mock OK) | ✅ Day 1 |
| T3.1 | `src/reproducer/bundler.py` | Capability 3 — bundle + 3× replay | Person 1 runner + `ExecutionResult` | Phase 2 (Day 1 with mocks) |
| T3.3 | `src/regression_gen/generator.py` | Capability 3 — regression suite | T3.2 | Phase 2 |

Deliverables (from doc 02): reproducer bundler + 3× replay verifier · ddmin minimizer with crash-signature equivalence predicate · regression test promoter · ELF NX/PIE/RELRO/Canary analyzer + downgrade detector · defense prep.

## 2. Contracts & Interfaces (lock on Day 1, T0)

- **Consumed:** `ExecutionResult` (Person 1 → us): `test_id, version, build_type, exit_code, signal, timed_out, oom_killed, crashed, error_type, detection_mechanism, stack_trace: List[StackFrame(function, file, line)], stdout, stderr`.
- **Produced:** `ReproducerArtifact` (us → Person 4): `finding_id, bundle_dir, deterministic_replays, is_flaky, original_size_bytes, minimized_size_bytes, minimized_input_path, regression_test_path, hardening_report`.
- **Executor protocol (our decoupling key):** define a `RunnerPort` with `run(input_bytes: bytes, *, version, build_type, timeout_sec) -> ExecutionResult`. Code all of our modules against this interface. Day 1 = `MockRunner` (scripted `ExecutionResult`s); Person 1's Docker sandbox plugs in later with zero changes to our logic.
- **Flaky handling:** if replays < 3/3, set `is_flaky=True` → finding is `Inconclusive` → exit code **40** (Person 4's orchestrator applies the code; we only set the flag).

## 3. Build Order

### Phase 1 — Wed Nov 12 (today): fully independent modules

**Step 0 — Skeleton & schema sync (30 min, with team)**
- [x] Draft `src/models.py` dataclasses (T0) — all `ExecutionResult` + `ReproducerArtifact` fields from doc 03, plus `RunnerPort` protocol and `crash_signature()`. Schema unit tests included. *(Team agreement on field names still pending at sync.)*
- [x] Create `src/hardening/`, `src/minimizer/`, `src/reproducer/`, `src/regression_gen/`, `tests/` skeleton; repo-local venv at `.venv/` with pyelftools + pytest (`requirements.txt`, `pyproject.toml`).

**Step 1 — T3.4 `src/hardening/elf_checker.py` (independent, finish today)**
- [x] `HardeningReport` dataclass: `binary_path, sha256, nx: {enabled, evidence}, pie: {enabled, evidence}, relro: {None|Partial|Full, evidence}, canary: {present, evidence}, caveats: List[str]`.
- [x] Evidence extraction via **pyelftools** (fallback: `readelf -W -l -d -s` subprocess parsing):
  - **NX** — `GNU_STACK` segment: `RW` = enabled, `RWE` = disabled.
  - **PIE** — header `e_type == ET_DYN` + `DF_1_PIE` in dynamic flags; `ET_EXEC` = disabled. Caveat: PIE ≠ ASLR enabled on the OS.
  - **RELRO** — Full = `GNU_RELRO` segment **and** immediate binding via any of `DT_BIND_NOW`, `DF_1_NOW` (DT_FLAGS_1), or `DF_BIND_NOW` (DT_FLAGS — older linkers, both pyelftools and readelf paths); Partial = `GNU_RELRO` only; else None.
  - **Canary** — `__stack_chk_fail` (imported symbol) / `__stack_chk_guard` present. Caveat: symbol presence ≠ every function instrumented.
- [x] Edge cases: stripped binaries (use dynamic section, not symtab), static binaries (no `PT_DYNAMIC` → symtab), missing/corrupt file → clean error.
- [x] `compare_hardening(base_report, patched_report) -> List[HardeningDelta]` — emit **HARDENING_REGRESSION** warning for any downgrade (Full→Partial RELRO, canary removed, NX/PIE disabled), informational note on upgrades.
- [x] **Tests:** compile tiny C fixtures with flag matrix (`default` vs `-fno-stack-protector`, `-no-pie`, `-Wl,-z,norelro` vs `-Wl,-z,relro,-z,lazy` vs `-Wl,-z,relro,-z,now`, `-Wl,-z,execstack`) → assert every field + downgrade detection + readelf fallback parity.

**Step 2 — T3.2 `src/minimizer/ddmin.py` core (algorithm today, real runner later)**
- [x] Zeller's `ddmin(initial: bytes, test: Callable[[bytes], bool]) -> bytes` — chunk-deletion loop, `n=2` start, grow `n` on no-reduction, terminate when `n ≥ len(input)`. Docstring the O(n²) behavior. *(Combined-review round: the empty input is now tested once after the chunk loop, so one-byte inputs can reduce to empty; skipped when the iteration budget is exhausted.)*
- [x] Crash-equivalence predicate `CrashSignaturePredicate`: **identical `error_type` AND identical top frame (function + file + line)**. Accept a candidate only if signature matches the original. *Exit-code-only checking is explicitly forbidden by Section 3.3 — never implement it as the default; `strict=False` is a debug-only lax mode.*
- [ ] Safety caps: per-run timeout, `max_iterations`, overall minimization budget (each candidate = one process run). *(capped via `max_iterations`; per-run timeout rides on the runner call — wire in Phase 2.)*
- [ ] Reduction strategies (cheap first): line-based chunking for text inputs → byte-level ddmin for binary inputs → single-byte greedy sweep as final polish. *(byte-level ddmin done; line-based pre-pass is Phase 2 polish.)*
- [x] **Tests (Day 1, no Docker):** `MockRunner` + pure-predicate tests — ddmin shrinks 4 KB marker input to `b"PWNME"`, rejects different error_type/crash-line candidates, lax mode, iteration budget. *(Real C fixture end-to-end lands with `LocalExecutor` in Phase 2.)*

### Phase 2 — Thu Nov 13: runner-dependent modules

**Step 3 — T3.1 `src/reproducer/bundler.py`**
- [x] `verify_reproducibility(runner, input_bytes, original, *, finding_id, n=3, timeout_sec) -> ReplayReport` — N replays (configurable, default 3) under identical settings; a replay matches only on same error_type AND same top frame; timeouts/OOM never count; `is_flaky = not all matched`.
- [x] ddmin integration (`minimize_input`): strict crash-signature predicate + **revalidation** of the minimized bytes before saving; flaky crashes skip minimization and keep the original input.
- [x] `create_bundle(...) -> ReproducerArtifact` producing `reproducers/<finding_id>/`:
  - `crashing_input.bin` + `minimized_input.bin` + copied `binary` (executable, SHA-256 recorded)
  - `metadata.json`: base/patched commit hashes, `binary_sha256`, `DT_NEEDED` runtime dependencies, `build_type`, `compile_flags`, `env_vars`, `cli_command`, `input_mode`, argv template, crash signature, full replay results, input sizes, minimization stats
  - `reproduce.sh`: standalone POSIX sh, works from any cwd, `./reproduce.sh` / `./reproduce.sh minimized`, all three input modes, eval-free with `shlex.quote` (argv mode: whitespace-split, null-byte limitation documented in the header)
  - finding IDs validated (charset + traversal guard on the resolved path)
- [x] **Shared strict-equivalence rule** (`strict_crash_match` + `sufficient_crash_evidence` in models.py, used by both replay verification and the ddmin predicate): requires crashed=True, no timeout/OOM, an error type, and the same top frame (line compared only when both sides have it). Timeouts/OOM never match, even with crashed=True; missing diagnostics never match — no exit-code-only fallback. Insufficient evidence → minimization skipped (`insufficient_crash_evidence`), finding inconclusive.
- [x] **Replay provenance (combined-review round):** `ReplayReport` carries `test_id`/`version`/`build_type` (None defaults so older evidence still deserializes); `verify_reproducibility()` populates them and raises on runner results that don't match the requested context; bundle metadata serializes them; the classifier rejects mismatched provenance and treats missing provenance as non-confirming; the regression generator requires provenance in bundle metadata and checks version/build_type against the bundle. Older bundles are rejected conservatively, never inferred.
- [x] **Execution-context enforcement in minimization & verification (combined-review round 2):** shared `assert_execution_context()` rule — every `CrashSignaturePredicate` run (incl. final revalidation and lax mode) validates returned version/build_type/test_id; any version/build/test change from the original signature is refused with no override escape hatch (obtain a real `ExecutionResult` from the new context instead); `verify_regression()` validates each returned result's version/build_type, and BOTH expectations must carry an expected `test_id` (persisted in new manifest entries from bundle replay provenance) — legacy entries without provenance are rejected before any execution, never inferred. Violations raise, never ok=True.
- [x] **Nondeterminism after replays:** ddmin raises `MinimizationError` (a `ValueError` subclass) when the initial predicate check fails; the bundler catches exactly that type, keeps the original input + 3/3 replay evidence, records `nondeterministic_precheck_failed`, and marks the finding inconclusive. Failed final revalidation handled the same way. Any skipped minimization ⇒ `artifact.is_flaky=True`.
- [x] **Env-var safety in reproduce.sh:** target env vars are applied only to the child process via `env` (never `export`), so target variables named `INPUT`/`BINARY`/`SCRIPT_DIR`/`NAME` cannot hijack the script; names validated against `[A-Za-z_][A-Za-z0-9_]*`, null bytes rejected.
- [x] Flaky path: still write the bundle (original input as minimized fallback), set `is_flaky=True`, record `minimization.skipped` + reason (finding → Inconclusive → exit 40 downstream).
- [ ] **Fallback while Person 1's Docker runner is missing:** `LocalExecutor` (subprocess + `resource` limits + minimal signal/exit parser) behind the same `RunnerPort` — demoed inline in the end-to-end bundle run; promote to `src/reproducer/local_runner.py` when regression_gen lands.
- [x] **Tests:** deterministic 3/3, partial 2/3, changed signature, timeout (incl. crashed+timed_out), OOM, replay count N, exact input bytes, binary hashes, unsafe finding IDs, argv-template validation, output roots with spaces, env quoting, generated `reproduce.sh` executed against real compiled C fixtures (stdin/file/args) from a different cwd, insufficient-evidence skips, nondeterministic precheck/revalidation preservation, and env-var collision with script internals — 94/94 passing.

**Step 4 — T3.3 `src/regression_gen/generator.py`**
- [x] `promote_to_regression_suite(artifact, expectation, *, suite_root, replace=False) -> ManifestEntry` — copies the minimized input to `<suite_root>/auto_generated/<finding_id>_minimized.bin` (byte-exact) and atomically updates `manifest.json` (format 1, `entries` keyed by finding_id): finding ID, relative input path, input SHA-256, source bundle, commit/build provenance, input mode + argv template, build type, explicit per-version expectations, expected crash signature (resolved from the bundle or per-version override), created_at.
- [x] Eligibility gates: `is_flaky=True` rejected even with `deterministic_replays="3/3"`; bundle metadata must show `minimization.skipped=False`, `revalidated=True`, `replay.matching == total` and must agree with the artifact; missing/corrupted metadata and missing input files raise clear `RegressionError`s; finding IDs validated (charset + no traversal); a corrupted or structurally wrong existing manifest is never overwritten.
- [x] **Bundle binding (hardening round 2):** finding IDs must agree across artifact, bundle directory name, and metadata; the minimized input must be a regular, non-symlink file (an `is_symlink()` check on the input itself — a symlink named `minimized_input.bin` is rejected even when it targets a same-sized file inside the bundle; symlinked ancestor directories remain supported), its resolved path must be the bundle's `minimized_input.bin`; recorded sizes (artifact + metadata) must equal actual file sizes — structural consistency only, equal sizes do not prove content integrity; no bundle-metadata content hashes were added, so older bundles need no migration.
- [x] **Strict replay-evidence validation (hardening round 2):** positive integer `total`/`matching` (booleans rejected), `matching == total`, `deterministic is exactly True`, `is_flaky is exactly False`, agreement with `artifact.deterministic_replays`, exactly `total` records with unique attempts in `1..total`, and every record a matching crash without timeout/OOM whose signature is strictly consistent with the original crash (shared `strict_crash_match`); any replay count ≥ 1 accepted — no hardcoded 3.
- [x] **Crash-consistent publication (hardening round 2):** inputs are content-addressed (`<finding_id>_minimized_<sha256[0:16]>.bin`) so new content never overwrites a file the current manifest references; the manifest is atomically replaced only after the new input is on disk; a failed publish leaves the old manifest and all its files usable; replaced/leftover versioned files are documented orphans (manifest is authoritative).
- [x] **Input integrity before execution (hardening round 2):** `verify_manifest_entry()` hashes the supplied bytes against `entry.input_sha256` before any runner call; on mismatch it raises `RegressionError` with zero executions.
- [x] Idempotency & conflicts: an identical re-promotion is a no-op returning the stored entry; a conflicting entry (or a tampered input file) requires `replace=True`; multiple findings coexist without losing entries; writes are atomic (temp + `os.replace`). Concurrent writers are documented as unsupported (read-modify-write is unlocked).
- [x] Explicit expectations (`VersionExpectation` per version): crash=True (signature from bundle or explicit override — supports new issues crashing only in patched) or crash=False with a required explicit `exit_code` (nonzero allowed for valid input rejection); no all-clean entries; no exit-code-only matching; functional correctness judged only by the explicit expectation, never by absence of a crash. *(Combined-review round: shared strict validation for both the Python API and manifest deserialization — crash must be an actual bool, exit_code an actual int, 'crash' is a required manifest field, unsupported manifest formats and malformed entries are rejected before any runner call or suite write.)*
- [x] Verification helpers: `verify_regression(runner, input_bytes, expectation, *, build_type, timeout_sec) -> VerificationReport` and `verify_manifest_entry(...)` — run both versions through `RunnerPort`, check crash signatures via `strict_crash_match`, check explicit clean-run exit codes, timeout/OOM satisfy neither kind of expectation, per-version structured outcomes with reasons, runner exceptions propagate as infrastructure failures. *(Combined-review round: `verify_regression()` now validates BOTH expectations strictly — `VersionExpectation.validate(..., allow_unresolved_signature=False)` — before the first runner call, closing the direct-API bypass; malformed expectation objects fail cleanly; valid nonzero exit codes and infrastructure propagation preserved.)*
- [x] **Tests:** 141 tests — byte-exact promotion, flaky/missing/unrevalidated/inconsistent evidence rejection, idempotency, conflicts, multi-entry preservation, invalid IDs/traversal, corrupted manifests, signature match/mismatch, timeout/OOM with crashed=True, explicit nonzero exit codes, infrastructure propagation, manifest-entry round-trip, hash-integrity check with zero runner calls, bundle binding (foreign paths, ID/dir mismatches, size mismatches, symlink escapes incl. same-sized in-bundle targets and dangling links, symlinked ancestor dirs), strict replay-evidence validation (counts, flags, records, provenance, configurable N=5), strict expectation/manifest validation (non-bool crash, bool/string exit codes, missing fields, unsupported formats, malformed signatures), execution-context enforcement (wrong test_id/version/build_type in predicate runs, no override escape hatch, new-baseline construction, final revalidation, swapped regression results, required expected test provenance with zero runner calls), failed-publish consistency, and a real integration round-trip (compiled C crash/safe fixtures + test-only runner, no Docker, deliberately no production LocalExecutor) — 368/368 passing with Persons 2 and 4's suites.

### Phase 3 — Fri Nov 14: integration & defense rehearsal

- [ ] Wire our `RunnerPort` to Person 1's sandbox; run Stage 5 (replay → ddmin → bundle → regression export) end-to-end on one real crash.
- [ ] Hand `ReproducerArtifact` + `HardeningReport` to Person 4 for `report.json`; confirm hardening tables appear in the report.
- [ ] Full 8-scenario matrix via `run_all_scenarios.sh` — check our artifacts in every scenario (correct, incomplete, regression) and the exit codes 0/10/20/30/40.
- [ ] Unseen-patch rehearsal on 2 held-out patches (zero hardcoded assumptions).
- [ ] Defense drills (below).

## 4. Testing Strategy

- **Unit:** `pytest` per module — ddmin (mock executor), bundler (mock runner), generator (tmp dirs), elf_checker (compiled C fixtures). No Docker required for the whole unit suite.
- **Integration:** against `LocalExecutor` first, Person 1's Docker sandbox second.
- **Schema guard:** one test asserting `ExecutionResult`/`ReproducerArtifact` field shape stays in sync with `src/models.py`.

## 5. Defense Prep (Section 6.2 — 3 axes)

- **Axis 1 (architecture):** be able to whiteboard each module — why the executor protocol decouples us, why ddmin preserves the crash *signature* (not just non-zero exit), what evidence each hardening check reads from the ELF.
- **Axis 2 (finding analysis):** pick a finding from a real run and trace: replay_results 3/3 → minimized vs original sizes → identical error_type + top frame → hardening table row.
- **Axis 3 (live modification, rehearse each under 3 min):**
  1. Tighten the ddmin equivalence predicate live (e.g., also require same `detection_mechanism`) and re-run minimization.
  2. Change replay count N (3 → 5) and re-run the bundler.
  3. Rebuild a target with `-fno-stack-protector` or `-Wl,-z,norelro` and show the HARDENING_REGRESSION warning appear live.

## 6. Risks & Fallbacks

| Risk | Fallback |
| --- | --- |
| Person 1's Docker runner not ready | `LocalExecutor` behind the same `RunnerPort`; swap in later |
| `models.py` fields drift | T0 agreement + schema unit test |
| ddmin too slow on large inputs | line-chunk first, iteration/timeout caps |
| Binary stripped/static (hardening) | dynamic-section-first logic + readelf fallback |
| No Docker locally during dev | elf_checker and all unit tests need no Docker at all |

## 7. Deliverable Checklist (from doc 02)

- [x] `src/reproducer/bundler.py` — bundle generator + 3× replay stability checker
- [x] `src/minimizer/ddmin.py` — Delta Debugging minimizer with crash-signature equivalence predicate
- [x] `src/regression_gen/generator.py` — automated regression test promoter
- [x] `src/hardening/elf_checker.py` — NX/PIE/RELRO/Canary analyzer + differential downgrade detector
- [ ] Individual defense prep: predicate tweak, replay-count change, hardening-regression live demo
