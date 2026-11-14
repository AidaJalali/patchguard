# Person 1 integration

The `sahand` branch is merged with its original history preserved, despite its independently initialized Git root. Shared models and project setup were reconciled with the existing Persons 2–4 implementation.

## Canonical contracts

All Python code uses the existing top-level imports under `PYTHONPATH=src` (`models`, `builder`, `runner`, etc.). Do not mix these with `src.models`: importing a second copy creates different dataclass identities.

- `TargetConfig` and `BuildArtifact` from Person 1 were added to `models`.
- `StackFrame` remains `index`, `function`, `file`, `line`.
- `ExecutionResult.signal` remains an integer signal number or `None`; diagnostics normalize signal names to numbers.
- `ExecutionResult` now also preserves `duration_ms` and `cli_command`.
- One pytest configuration remains in `pyproject.toml`; Person 1's tests use the same import layout and contracts.

## Runner adapter

`DockerSandboxRunner.run(artifact, config, test_id, input_bytes, args)` remains available. Use `TargetRunnerAdapter` to expose the common `RunnerPort` API used by replay/minimization/regression verification:

```python
from builder.builder import DualBuilder
from config.loader import load_target_config
from runner.adapter import TargetRunnerAdapter

config = load_target_config("target.yaml")
artifacts = DualBuilder().build_all(config, ".work/target")
runner = TargetRunnerAdapter(artifacts, config, test_id="poc-1")
result = runner.run(b"payload", version="base", build_type="sanitized", timeout_sec=5)
```

The adapter is bound to one test ID. It chooses the correct artifact, forwards the input, applies the requested timeout without mutating the original config, and checks returned execution provenance. Missing artifacts are build/config errors (code 30). Optional `argv_template` uses the literal `{input}` placeholder: exactly once for file/args, never for stdin. File mode maps it to `/work/input.bin`. Args mode splits on ASCII spaces/tabs/newlines with no shell quote interpretation, matching bundled `reproduce.sh`; null bytes are rejected. Use the same template when constructing `FindingContext`.

## Validation

The combined suite includes the original Person 1 configuration/diagnostic tests and four Docker tests, plus adapter tests and a cross-module round trip. The latter uses real Git snapshots, four GCC builds, ASan output parsed by the production diagnostics parser, replay, minimization, regression promotion/verification, Clang correlation, classification, and reporting. Only this test's Docker build/run transport is replaced by local execution of its generated C fixture; no production local executor is introduced.

Production build and target execution remain in Docker. Build the image before running its integration tests:

```bash
docker build -t patchguard-sandbox:latest .
.venv/bin/python -m pytest -q
```

The CI Docker job builds the image and runs Person 1 plus cross-module integration tests separately. During local integration, downloading the Ubuntu image failed with a registry HTTP 403. The four container tests were therefore skipped, not claimed as passing; the host-compiled cross-module test ran successfully.

The complete `validate` command and the two-target scenario matrix are implemented and verified in `src/validation.py` and `run_all_scenarios.sh`; see docs 09 and 10 for setup, schema, and the verified scenario results.
