"""Shared exceptions for the patch_validator pipeline."""


class ConfigOrBuildError(Exception):
    """Raised on invalid configuration or build failure (exit code 30)."""

    BUILD_OR_CONFIG_ERROR = 30

    def __init__(self, message: str, code: int = BUILD_OR_CONFIG_ERROR) -> None:
        self.code = code
        self.message = message
        super().__init__(message)
