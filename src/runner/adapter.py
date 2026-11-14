import math
from dataclasses import replace

from exceptions import ConfigOrBuildError
from models import (
    BuildArtifact,
    ExecutionResult,
    TargetConfig,
    assert_execution_context,
)
from runner.sandbox import DockerSandboxRunner, input_to_args


class TargetRunnerAdapter:
    def __init__(
        self,
        artifacts: dict[tuple[str, str], BuildArtifact],
        config: TargetConfig,
        *,
        test_id: str,
        sandbox: DockerSandboxRunner | None = None,
        argv_template: list[str] | None = None,
    ) -> None:
        if not isinstance(test_id, str) or not test_id:
            raise ValueError("test_id must be a nonempty string")
        if config.input_mode not in ("stdin", "file", "args"):
            raise ValueError("unsupported input mode")
        self.artifacts = dict(artifacts)
        for key, artifact in self.artifacts.items():
            if key != (artifact.version, artifact.build_type):
                raise ValueError("artifact key does not match its execution context")
        self.config = config
        self.test_id = test_id
        images = {artifact.sandbox_image for artifact in self.artifacts.values() if artifact.sandbox_image}
        if len(images) > 1:
            raise ValueError("build artifacts must share the same sandbox image")
        self.sandbox = sandbox if sandbox is not None else (
            DockerSandboxRunner(image=next(iter(images))) if images else DockerSandboxRunner()
        )
        self.argv_template = (
            list(argv_template)
            if argv_template is not None
            else ([] if config.input_mode == "stdin" else ["{input}"])
        )
        expected = 0 if config.input_mode == "stdin" else 1
        if self.argv_template.count("{input}") != expected or any(
            not isinstance(arg, str) or "\0" in arg for arg in self.argv_template
        ):
            raise ValueError("invalid argv_template for the configured input mode")

    def run(
        self,
        input_bytes: bytes,
        *,
        version: str,
        build_type: str,
        timeout_sec: float,
    ) -> ExecutionResult:
        if not math.isfinite(timeout_sec) or timeout_sec <= 0:
            raise ValueError("timeout_sec must be finite and positive")
        try:
            artifact = self.artifacts[(version, build_type)]
        except KeyError as exc:
            raise ConfigOrBuildError(
                f"missing build artifact for {version}/{build_type}"
            ) from exc
        args = []
        for arg in self.argv_template:
            if arg == "{input}":
                args.extend(
                    ["/work/input.bin"]
                    if self.config.input_mode == "file"
                    else input_to_args(input_bytes)
                )
            else:
                args.append(arg)
        result = self.sandbox.run(
            artifact,
            replace(self.config, timeout_sec=timeout_sec),
            test_id=self.test_id,
            input_bytes=input_bytes,
            args=args,
        )
        assert_execution_context(
            result, version=version, build_type=build_type, test_id=self.test_id
        )
        return result
