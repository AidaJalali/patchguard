from __future__ import annotations

import os
from pathlib import Path


def paths_overlap(a: str | Path, b: str | Path) -> bool:
    first, second = Path(a).resolve(), Path(b).resolve()
    return first == second or first in second.parents or second in first.parents


def paths_alias(a: Path, b: Path) -> bool:

    try:
        return os.path.samefile(a, b)
    except OSError:
        pass
    return Path(os.path.abspath(a)).resolve() == Path(os.path.abspath(b)).resolve()
