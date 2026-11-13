from __future__ import annotations

import os
from pathlib import Path


def paths_alias(a: Path, b: Path) -> bool:

    try:
        return os.path.samefile(a, b)
    except OSError:
        pass
    return Path(os.path.abspath(a)).resolve() == Path(os.path.abspath(b)).resolve()
