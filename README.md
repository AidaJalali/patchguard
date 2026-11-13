# patchguard
Automated security patch validation and regression testing for C/C++ applications in CI/CD pipelines.

## Person 1 foundation (build, sandbox, diagnostics)

```text
src/
  models.py              # Shared dataclasses (TargetConfig, BuildArtifact, ExecutionResult, ...)
  exceptions.py          # ConfigOrBuildError (exit code 30)
  config/loader.py       # YAML/JSON target config loader
  builder/builder.py     # DualBuilder — base/patched × release/sanitized
  runner/sandbox.py      # DockerSandboxRunner — cgroup/network-isolated execution
  diagnostics/parser.py  # ASan/UBSan/canary/signal/timeout/OOM classification
Dockerfile               # ubuntu:24.04 linux/amd64 sandbox image
```

### Setup

```bash
pip install -r requirements.txt
docker build -t patchguard-sandbox:latest .
pytest tests/test_person1.py -q
```

Integration tests that compile and run C targets require Docker Desktop (linux/amd64) and the `patchguard-sandbox:latest` image.

## Documentation

Project planning documents live in [`docs/`](docs/):

| Document | Description |
| --- | --- |
| [Project 1 Specification](<docs/پروژه ۱ - صورت پروژه (Project 1 Specification).pdf>) | Official project statement (Persian) |
| [Easy-Language Explanation of Project 1](<docs/01 - Easy-Language Explanation of Project 1.docx>) | Plain-language walkthrough of the project goals |
| [4-Person Task Breakdown, Structure & Deliverables](<docs/02 - 4-Person Task Breakdown, Structure & Deliverables.docx>) | Per-member task split, structure, and deliverables |
| [Overall Architecture, Timeline & Task Dependencies](<docs/03 - Overall Architecture, Timeline & Task Dependencies.docx>) | Architecture overview, schedule, and task dependencies |
