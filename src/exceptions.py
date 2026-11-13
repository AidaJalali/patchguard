class ConfigOrBuildError(Exception):
    BUILD_OR_CONFIG_ERROR = 30

    def __init__(self, message: str, code: int = BUILD_OR_CONFIG_ERROR) -> None:
        self.code = code
        self.message = message
        super().__init__(message)
