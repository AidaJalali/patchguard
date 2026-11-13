from dataclasses import dataclass, field
from pathlib import PurePosixPath

from diff_parser.diff_analyzer import PatchDiff
from models import ExecutionResult, StackFrame


@dataclass
class DiffCorrelation:
    finding_id: str
    correlation_confidence: str
    matched_diff_files: list[str] = field(default_factory=list)
    matched_functions: list[str] = field(default_factory=list)
    evidence_explanation: str = ""
    mechanism: str = "unproven"

    @property
    def proven(self) -> bool:
        return self.correlation_confidence in ("HIGH", "MEDIUM")


def _file_matches(actual: str | None, expected: str) -> bool:
    if not actual:
        return False
    a, e = PurePosixPath(actual).as_posix(), PurePosixPath(expected).as_posix()
    return a == e or a.endswith("/" + e)


def correlate(
    finding_id: str,
    result: ExecutionResult,
    patch: PatchDiff,
    *,
    depth: int = 2,
    line_radius: int = 3,
    extra_frames: tuple[StackFrame, ...] = (),
    base_coverage: set[tuple[str, int]] | None = None,
    patched_coverage: set[tuple[str, int]] | None = None,
) -> DiffCorrelation:

    if depth not in (1, 2) or line_radius < 0:
        raise ValueError("depth must be 1/2 and line_radius nonnegative")
    if result.version not in ("base", "patched"):
        raise ValueError("unknown execution version")

    def evidence(confidence, functions, explanation, mechanism):
        return DiffCorrelation(
            finding_id,
            confidence,
            sorted({f.file for f in functions}),
            sorted({f.name for f in functions}),
            explanation,
            mechanism,
        )

    if patch.diagnostics:
        return evidence(
            "INCONCLUSIVE",
            [],
            "Source analysis incomplete: " + "; ".join(patch.diagnostics),
            "unproven",
        )
    functions = patch.functions(result.version)
    modified = patch.modified_functions(result.version)

    def candidates(frame):
        matches = [
            f
            for f in functions
            if f.name == frame.function
            and (not frame.file or _file_matches(frame.file, f.file))
            and (frame.line is None or f.start_line <= frame.line <= f.end_line)
        ]

        return matches if len(matches) == 1 else []

    frames = result.stack_trace + list(extra_frames)
    for index, frame in enumerate(frames):
        for function in candidates(frame):
            if function not in modified:
                continue
            if index == 0 or index >= len(result.stack_trace):
                change = next(c for c in patch.files if c.path == function.file)
                near = (
                    frame.file
                    and frame.line is not None
                    and any(
                        interval
                        and interval[0] - line_radius
                        <= frame.line
                        <= interval[1] + line_radius
                        for interval in (
                            h.interval(result.version) for h in change.hunks
                        )
                    )
                )
                if near:
                    return evidence(
                        "HIGH",
                        [function],
                        "Crash/allocation/free frame is inside a modified function near changed lines.",
                        "direct_frame",
                    )
            return evidence(
                "MEDIUM",
                [function],
                "An observed stack frame identifies a modified function.",
                "stack_frame",
            )
    graph = patch.call_graph(result.version)
    for frame in frames:
        for function in candidates(frame):
            for changed in modified:
                frontier = {changed.key}
                for hops in range(1, depth + 1):
                    frontier = {v for u in frontier for v in graph.get(u, ())}
                    if function.key in frontier:
                        return evidence(
                            "MEDIUM",
                            [changed, function],
                            f"Modified caller reaches observed frame through {hops} static call edge(s).",
                            "call_graph",
                        )
    if (
        base_coverage is not None
        and patched_coverage is not None
        and base_coverage != patched_coverage
    ):
        touched = []
        for change in patch.files:
            for path, line in patched_coverage:
                if not _file_matches(path, change.path):
                    continue
                if any(
                    i and i[0] <= line <= i[1]
                    for i in (h.interval("patched") for h in change.hunks)
                ):
                    touched.extend(
                        f
                        for f in change.modified_functions("patched")
                        if f.start_line <= line <= f.end_line
                    )
        if touched:
            return evidence(
                "MEDIUM",
                touched,
                "Differing base/patched execution coverage includes a changed patched line.",
                "differential_coverage",
            )
    return evidence(
        "INCONCLUSIVE",
        [],
        "No unambiguous stack, call-graph, or differential coverage link to the patch.",
        "unproven",
    )
