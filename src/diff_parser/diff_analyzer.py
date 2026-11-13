from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath


class DiffError(ValueError):
    pass


@dataclass(frozen=True)
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int

    def interval(self, version: str) -> tuple[int, int] | None:
        if version not in ("base", "patched"):
            raise ValueError("version must be base or patched")
        start, count = (
            (self.old_start, self.old_count)
            if version == "base"
            else (self.new_start, self.new_count)
        )
        return (start, start + count - 1) if count else None


@dataclass(frozen=True)
class CallTarget:
    name: str
    symbol: str | None
    linkage: str


@dataclass(frozen=True)
class FunctionSpan:
    file: str
    name: str
    start_line: int
    end_line: int
    calls: tuple[str, ...] = ()
    linkage: str = "unknown"
    symbol: str | None = None
    call_targets: tuple[CallTarget, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.file}:{self.symbol or self.name}:{self.start_line}"


@dataclass
class FileDiff:
    path: str
    hunks: list[Hunk]
    base_functions: list[FunctionSpan] = field(default_factory=list)
    patched_functions: list[FunctionSpan] = field(default_factory=list)

    def modified_functions(self, version: str) -> list[FunctionSpan]:
        functions = self.base_functions if version == "base" else self.patched_functions
        intervals = []
        for hunk in self.hunks:
            interval = hunk.interval(version)
            if interval is None:


                point = hunk.old_start if version == "base" else hunk.new_start
                interval = (point, point)
            intervals.append(interval)
        return [
            f
            for f in functions
            if any(i and f.start_line <= i[1] and i[0] <= f.end_line for i in intervals)
        ]


@dataclass
class PatchDiff:
    files: list[FileDiff]
    diagnostics: list[str] = field(default_factory=list)

    def functions(self, version: str) -> list[FunctionSpan]:
        if version not in ("base", "patched"):
            raise ValueError("version must be base or patched")
        return [
            f
            for change in self.files
            for f in (
                change.base_functions if version == "base" else change.patched_functions
            )
        ]

    def modified_functions(self, version: str) -> list[FunctionSpan]:
        return [f for change in self.files for f in change.modified_functions(version)]

    def call_graph(self, version: str) -> dict[str, set[str]]:

        functions = self.functions(version)
        graph = {f.key: set() for f in functions}
        for caller in functions:
            targets = caller.call_targets or tuple(
                CallTarget(n, None, "unknown") for n in caller.calls
            )
            for target in targets:
                candidates = [f for f in functions if f.name == target.name]
                if target.symbol is not None:
                    candidates = [f for f in candidates if f.symbol == target.symbol]
                if target.linkage == "internal":
                    candidates = [
                        f
                        for f in candidates
                        if f.file == caller.file and f.linkage == "internal"
                    ]
                else:
                    candidates = [
                        f
                        for f in candidates
                        if f.file == caller.file
                        or (target.linkage == "external" and f.linkage == "external")
                    ]
                    local = [f for f in candidates if f.file == caller.file]
                    candidates = local or candidates
                if len(candidates) == 1:
                    graph[caller.key].add(candidates[0].key)
        return graph

    def neighborhood(self, version: str, depth: int = 2) -> set[str]:
        if depth not in (1, 2):
            raise ValueError("correlation depth must be 1 or 2")
        graph = self.call_graph(version)
        nodes = {f.key for f in self.modified_functions(version)}
        for _ in range(depth):
            nodes |= {v for u, vs in graph.items() for v in vs if u in nodes} | {
                u for u, vs in graph.items() if vs & nodes
            }
        return nodes


def parse_hunks(unified_diff: str) -> list[Hunk]:

    return [
        Hunk(int(m[1]), int(m[2] or 1), int(m[3]), int(m[4] or 1))
        for m in re.finditer(
            r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", unified_diff, re.M
        )
    ]


def extract_functions(
    source: str,
    *,
    file: str,
    compiler: str = "clang",
    compile_args: tuple[str, ...] = (),
    timeout_sec: float = 30,
    include_root: str | Path | None = None,
) -> list[FunctionSpan]:

    if any(
        not arg.startswith(("-I", "-D", "-U", "-std=", "-W", "-fno-", "-m"))
        for arg in compile_args
    ):
        raise DiffError(
            "compile_args support attached -I/-D/-U, -std=, -W, -fno-, -m flags only"
        )
    suffix = PurePosixPath(file).suffix or ".c"
    with tempfile.TemporaryDirectory(prefix="patchguard-ast-") as tmp:
        path = Path(tmp) / ("source" + suffix)
        path.write_text(source, encoding="utf-8")
        args = [compiler, "-fsyntax-only", "-Xclang", "-ast-dump=json", *compile_args]
        if include_root is not None:
            args += ["-iquote", str(include_root)]
        try:
            proc = subprocess.run(
                [*args, str(path)], capture_output=True, text=True, timeout=timeout_sec
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DiffError(f"AST analysis unavailable for {file}: {exc}") from exc
        if proc.returncode:
            raise DiffError(f"AST analysis failed for {file}: {proc.stderr.strip()}")
        try:
            root = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise DiffError(f"invalid compiler AST for {file}") from exc
        path_string = str(path)
        functions = []
        declarations = {}

        def index_declarations(node, anonymous_namespace=False):
            anonymous_namespace = anonymous_namespace or (
                node.get("kind") == "NamespaceDecl" and not node.get("name")
            )
            if node.get("kind") in (
                "FunctionDecl",
                "CXXMethodDecl",
                "CXXConstructorDecl",
                "CXXDestructorDecl",
            ):
                internal = anonymous_namespace or (
                    node.get("kind") == "FunctionDecl"
                    and node.get("storageClass") == "static"
                )
                declarations[node["id"]] = CallTarget(
                    node.get("name", ""),
                    node.get("mangledName"),
                    "internal" if internal else "external",
                )
            for child in node.get("inner", []):
                index_declarations(child, anonymous_namespace)

        index_declarations(root)

        def walk(node, inherited_file=None):
            loc = node.get("loc", {})
            location_file = loc.get("file", inherited_file)

            included = "includedFrom" in loc
            inner = node.get("inner", [])
            body = next((n for n in inner if n.get("kind") == "CompoundStmt"), None)
            if (
                node.get("kind")
                in (
                    "FunctionDecl",
                    "CXXMethodDecl",
                    "CXXConstructorDecl",
                    "CXXDestructorDecl",
                )
                and body
            ):
                extent = node.get("range", {})
                begin, end = extent.get("begin", {}), extent.get("end", {})

                if (
                    not included
                    and location_file in (None, path_string)
                    and "offset" in begin
                    and "offset" in end
                ):
                    raw = source.encode("utf-8")
                    start = raw[: begin["offset"]].count(b"\n") + 1
                    finish = raw[: end["offset"]].count(b"\n") + 1
                    calls = set()
                    targets = set()

                    def callee_names(n):
                        ref = n.get("referencedDecl", {})
                        if ref.get("kind") in (
                            "FunctionDecl",
                            "CXXMethodDecl",
                        ) and ref.get("name"):
                            calls.add(ref["name"])
                            targets.add(
                                declarations.get(
                                    ref.get("id"),
                                    CallTarget(ref["name"], None, "unknown"),
                                )
                            )
                        if n.get("kind") == "MemberExpr" and n.get(
                            "referencedMemberDecl"
                        ):
                            calls.add(n["name"])
                            targets.add(
                                declarations.get(
                                    n["referencedMemberDecl"],
                                    CallTarget(n["name"], None, "unknown"),
                                )
                            )
                        for child in n.get("inner", []):
                            callee_names(child)

                    def references(n):
                        children = n.get("inner", [])
                        if (
                            n.get("kind") in ("CallExpr", "CXXMemberCallExpr")
                            and children
                        ):
                            callee_names(children[0])
                        for child in children:
                            references(child)

                    references(body)
                    identity = declarations[node["id"]]
                    functions.append(
                        FunctionSpan(
                            file,
                            node["name"],
                            start,
                            finish,
                            tuple(sorted(calls)),
                            identity.linkage,
                            identity.symbol,
                            tuple(
                                sorted(
                                    targets,
                                    key=lambda t: (t.name, t.symbol or "", t.linkage),
                                )
                            ),
                        )
                    )
            for child in inner:
                walk(child, location_file)

        walk(root)
        return functions


def analyze_sources(
    changes: dict[str, tuple[str | None, str | None, str]],
    *,
    compile_args: tuple[str, ...] = (),
    compiler: str = "clang",
    include_roots: dict[str, Path] | None = None,
) -> PatchDiff:

    files, diagnostics = [], []
    for path, (base, patched, diff) in changes.items():
        item = FileDiff(path, parse_hunks(diff))
        if PurePosixPath(path).suffix.lower() in (
            ".c",
            ".cc",
            ".cpp",
            ".cxx",
            ".h",
            ".hpp",
            ".hh",
            ".hxx",
        ):
            for version, source in (("base", base), ("patched", patched)):
                if source is None:
                    continue
                try:
                    root = include_roots.get(version) if include_roots else None
                    flags = tuple(
                        "-I" + str(root / arg[2:])
                        if root
                        and arg.startswith("-I")
                        and not Path(arg[2:]).is_absolute()
                        else arg
                        for arg in compile_args
                    )
                    functions = extract_functions(
                        source,
                        file=path,
                        compiler=compiler,
                        compile_args=flags,
                        include_root=root / PurePosixPath(path).parent
                        if root
                        else None,
                    )
                    setattr(item, f"{version}_functions", functions)
                except DiffError as exc:
                    diagnostics.append(f"{version}: {exc}")
        files.append(item)
    return PatchDiff(files, diagnostics)


def analyze_git(
    repo: str | Path,
    base: str,
    patched: str,
    *,
    compile_args: tuple[str, ...] = (),
    compiler: str = "clang",
) -> PatchDiff:

    def git(*args):
        proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
        if proc.returncode:
            raise DiffError(proc.stderr.decode(errors="replace").strip())
        return proc.stdout

    refs = [
        git("rev-parse", "--verify", "--end-of-options", ref + "^{commit}")
        .decode()
        .strip()
        for ref in (base, patched)
    ]
    raw = git("diff", "--name-status", "-z", "--no-renames", *refs, "--").split(b"\0")
    changes = {}
    for i in range(0, len(raw) - 1, 2):
        status, path = raw[i].decode(), raw[i + 1].decode("utf-8")

        def read(ref):
            return git("show", f"{ref}:{path}").decode("utf-8")

        try:
            changes[path] = (
                None if status == "A" else read(refs[0]),
                None if status == "D" else read(refs[1]),
                git(
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "--unified=0",
                    *refs,
                    "--",
                    path,
                ).decode("utf-8"),
            )
        except UnicodeDecodeError:
            changes[path] = (None, None, "")
    source_extensions = {
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hpp",
        ".hh",
        ".hxx",
        ".inc",
        ".ipp",
        ".tcc",
    }
    with tempfile.TemporaryDirectory(prefix="patchguard-trees-") as tmp:
        roots = {version: Path(tmp) / version for version in ("base", "patched")}
        snapshots = {}
        for version, ref in zip(("base", "patched"), refs):
            roots[version].mkdir()
            for record in git("ls-tree", "-rz", "--full-tree", ref).split(b"\0"):
                if not record:
                    continue
                info, name = record.split(b"\t", 1)
                mode, kind, oid = info.split()
                path = name.decode("utf-8")
                pure = PurePosixPath(path)
                if (
                    kind != b"blob"
                    or mode not in (b"100644", b"100755")
                    or pure.suffix.lower() not in source_extensions
                ):
                    continue
                if pure.is_absolute() or ".." in pure.parts:
                    raise DiffError("unsafe source path in git tree")
                content = git("cat-file", "blob", oid.decode())
                destination = roots[version] / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                if pure.suffix.lower() in (".c", ".cc", ".cpp", ".cxx"):
                    try:
                        snapshots.setdefault(path, {})[version] = content.decode(
                            "utf-8"
                        )
                    except UnicodeDecodeError:
                        pass

        for path, versions in snapshots.items():
            if path not in changes:
                changes[path] = (versions.get("base"), versions.get("patched"), "")
        return analyze_sources(
            changes, compile_args=compile_args, compiler=compiler, include_roots=roots
        )
