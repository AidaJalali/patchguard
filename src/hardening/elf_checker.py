from __future__ import annotations

import hashlib
import io
import re
import subprocess
from pathlib import Path

from models import HardeningCheck, HardeningDelta, HardeningReport

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000
DF_BIND_NOW = 0x8
PF_X = 0x1

RELRO_FULL = "Full"
RELRO_PARTIAL = "Partial"
RELRO_NONE = "None"

HARDENING_REGRESSION = "HARDENING_REGRESSION"
INFO = "INFO"

PIE_CAVEAT = (
    "PIE in the binary does not prove OS-level ASLR is enabled on the host kernel."
)
CANARY_CAVEAT = (
    "Presence of __stack_chk_fail/__stack_chk_guard does not prove every "
    "function is instrumented with a canary."
)


class HardeningError(Exception):
    pass


def inspect_elf(binary_path: str | Path) -> HardeningReport:

    path = Path(binary_path)
    if not path.is_file():
        raise HardeningError(f"binary not found: {path}")
    data = path.read_bytes()
    if not data.startswith(b"\x7fELF"):
        raise HardeningError(f"not an ELF file: {path}")
    sha256 = hashlib.sha256(data).hexdigest()

    try:
        __import__("elftools")
    except ImportError:
        return _inspect_with_readelf(path)

    try:
        facts = _inspect_with_pyelftools(data)
    except HardeningError:
        raise
    except Exception as exc:
        raise HardeningError(f"failed to parse ELF {path}: {exc}") from exc

    return _build_report(str(path), sha256, facts)


def _inspect_with_pyelftools(data: bytes) -> dict:
    from elftools.elf.elffile import ELFFile

    elf = ELFFile(io.BytesIO(data))

    def ptype(seg) -> bool:
        return seg["p_type"] in ("PT_GNU_STACK", PT_GNU_STACK)

    gnu_stack = next((seg for seg in elf.iter_segments() if ptype(seg)), None)
    if gnu_stack is None:
        nx_enabled, nx_evidence = None, "no PT_GNU_STACK segment found"
    else:
        flags = gnu_stack["p_flags"]
        nx_enabled = not (flags & PF_X)
        perms = "".join(
            ch for bit, ch in ((0x4, "R"), (0x2, "W"), (0x1, "E")) if flags & bit
        )
        nx_evidence = f"PT_GNU_STACK flags=0x{flags:x} ({perms})"

    e_type = elf.header["e_type"]
    flags1, bind_now, bind_now_evidence = _dynamic_tags(elf)
    pie_enabled = e_type == "ET_DYN" and bool(flags1 & DF_1_PIE)
    if flags1 & DF_1_PIE:
        pie_evidence = f"e_type={e_type}, DF_1_PIE set (DT_FLAGS_1=0x{flags1:x})"
    else:
        pie_evidence = f"e_type={e_type}, DF_1_PIE absent (DT_FLAGS_1=0x{flags1:x})"

    has_relro = any(
        seg["p_type"] in ("PT_GNU_RELRO", PT_GNU_RELRO) for seg in elf.iter_segments()
    )
    if has_relro and bind_now:
        relro, relro_evidence = (
            RELRO_FULL,
            f"PT_GNU_RELRO segment present + immediate binding via {bind_now_evidence}",
        )
    elif has_relro:
        relro, relro_evidence = (
            RELRO_PARTIAL,
            "PT_GNU_RELRO segment present, no immediate binding "
            "(DT_BIND_NOW / DF_1_NOW / DF_BIND_NOW)",
        )
    else:
        relro, relro_evidence = RELRO_NONE, "no PT_GNU_RELRO segment"

    canary_present, canary_evidence, extra_caveats = _canary_symbols(elf)

    return {
        "nx_enabled": nx_enabled,
        "nx_evidence": nx_evidence,
        "pie_enabled": pie_enabled,
        "pie_evidence": pie_evidence,
        "relro": relro,
        "relro_evidence": relro_evidence,
        "canary_present": canary_present,
        "canary_evidence": canary_evidence,
        "extra_caveats": extra_caveats,
    }


def _dynamic_tags(elf) -> tuple[int, bool, str]:

    from elftools.elf.dynamic import DynamicSection, DynamicSegment

    flags1 = 0
    flags = 0
    has_bind_now_tag = False

    dynamic_tables = [
        segment
        for segment in elf.iter_segments()
        if isinstance(segment, DynamicSegment)
    ]
    if not dynamic_tables:
        dynamic_tables = [
            section
            for section in elf.iter_sections()
            if isinstance(section, DynamicSection)
        ]
    for table in dynamic_tables:
        for tag in table.iter_tags():
            if tag["d_tag"] in ("DT_FLAGS_1", DT_FLAGS_1):
                flags1 |= tag["d_val"]
            elif tag["d_tag"] in ("DT_FLAGS", DT_FLAGS):
                flags |= tag["d_val"]
            elif tag["d_tag"] in ("DT_BIND_NOW", DT_BIND_NOW):
                has_bind_now_tag = True
    representations = []
    if has_bind_now_tag:
        representations.append("DT_BIND_NOW tag")
    if flags1 & DF_1_NOW:
        representations.append("DF_1_NOW in DT_FLAGS_1")
    if flags & DF_BIND_NOW:
        representations.append("DF_BIND_NOW in DT_FLAGS")
    evidence = " + ".join(representations)
    return flags1, bool(representations), evidence


def _canary_symbols(elf) -> tuple[bool, str, list[str]]:
    wanted = ("__stack_chk_fail", "__stack_chk_guard")
    found, where = [], []
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol.name in wanted and symbol.name not in found:
                found.append(symbol.name)
                where.append(f"{symbol.name} in {section_name}")

    if not where and elf.get_section_by_name(".dynsym") is None:
        from elftools.elf.dynamic import DynamicSegment

        for segment in elf.iter_segments():
            if (
                isinstance(segment, DynamicSegment)
                and next(segment.iter_tags("DT_SYMTAB"), None) is not None
            ):
                indices = set(range(segment.num_symbols()))

                for kind, table in segment.get_relocation_tables().items():
                    if kind == "RELR":
                        continue
                    indices.update(
                        relocation["r_info_sym"]
                        for relocation in table.iter_relocations()
                    )
                for index in sorted(indices):
                    symbol = segment.get_symbol(index)
                    if symbol.name in wanted and symbol.name not in found:
                        found.append(symbol.name)
                        where.append(f"{symbol.name} via PT_DYNAMIC")
    caveats = []
    if not where:
        caveats.append(
            "no .dynsym/.symtab symbol found — canary absent, or static/stripped "
            "binary with no symbol table available"
        )
    evidence = (
        ", ".join(where)
        if where
        else ("no __stack_chk_fail/__stack_chk_guard in .dynsym/.symtab")
    )
    return bool(found), evidence, caveats


def _inspect_with_readelf(path: Path) -> HardeningReport:

    data = path.read_bytes()
    proc = subprocess.run(
        ["readelf", "-W", "-h", "-l", "-d", "-s", str(path)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise HardeningError(f"readelf failed on {path}: {proc.stderr.strip()}")
    text = proc.stdout

    match = re.search(r"^\s*Type:\s+(\S+)", text, re.M)
    type_str = match.group(1) if match else "?"
    flags1_match = re.search(r"\(FLAGS_1\)\s+Flags:\s*([A-Z ]*)", text)
    flags1_names = flags1_match.group(1).split() if flags1_match else []

    flags_names = re.findall(r"\(FLAGS\)\s+([A-Z_][A-Z_ ]*)", text)
    flags_words = [name for line in flags_names for name in line.split()]
    bind_now_representations = []
    if "NOW" in flags1_names:
        bind_now_representations.append("DF_1_NOW (FLAGS_1)")
    if "BIND_NOW" in flags_words:
        bind_now_representations.append("DF_BIND_NOW (FLAGS)")
    if "(BIND_NOW)" in text:
        bind_now_representations.append("DT_BIND_NOW tag")
    bind_now = bool(bind_now_representations)
    pie_enabled = type_str.startswith("DYN") and "PIE" in flags1_names
    pie_evidence = (
        f"readelf Type: {type_str}; FLAGS_1: {' '.join(flags1_names) or 'none'}"
    )

    stack_match = re.search(r"^\s*GNU_STACK\s+(\S+\s+){5}(\S+)", text, re.M)
    if stack_match is None:
        nx_enabled, nx_evidence = None, "no GNU_STACK in readelf program headers"
    else:
        perms = stack_match.group(2)
        nx_enabled = "E" not in perms
        nx_evidence = f"readelf GNU_STACK {perms}"

    has_relro = "GNU_RELRO" in text
    if has_relro and bind_now:
        relro, relro_evidence = (
            RELRO_FULL,
            "readelf: PT_GNU_RELRO present + immediate binding via "
            + " + ".join(bind_now_representations),
        )
    elif has_relro:
        relro, relro_evidence = (
            RELRO_PARTIAL,
            "readelf: PT_GNU_RELRO present, no immediate binding",
        )
    else:
        relro, relro_evidence = RELRO_NONE, "readelf: no PT_GNU_RELRO segment"

    found = [
        name
        for name in ("__stack_chk_fail", "__stack_chk_guard")
        if re.search(rf"\b{re.escape(name)}\b", text)
    ]
    extra_caveats = (
        []
        if found
        else [
            "no canary symbol in readelf output — canary absent or static/stripped binary"
        ]
    )
    canary_evidence = (
        ", ".join(f"{name} (readelf symbol table)" for name in found)
        if found
        else "no __stack_chk_fail/__stack_chk_guard in readelf output"
    )

    return _build_report(
        str(path),
        hashlib.sha256(data).hexdigest(),
        {
            "nx_enabled": nx_enabled,
            "nx_evidence": nx_evidence,
            "pie_enabled": pie_enabled,
            "pie_evidence": pie_evidence,
            "relro": relro,
            "relro_evidence": relro_evidence,
            "canary_present": bool(found),
            "canary_evidence": canary_evidence,
            "extra_caveats": extra_caveats,
        },
    )


def _build_report(binary_path: str, sha256: str, facts: dict) -> HardeningReport:
    return HardeningReport(
        binary_path=binary_path,
        sha256=sha256,
        nx=HardeningCheck(facts["nx_enabled"], facts["nx_evidence"]),
        pie=HardeningCheck(facts["pie_enabled"], facts["pie_evidence"]),
        relro=facts["relro"],
        relro_evidence=facts["relro_evidence"],
        canary=HardeningCheck(facts["canary_present"], facts["canary_evidence"]),
        caveats=[PIE_CAVEAT, CANARY_CAVEAT, *facts["extra_caveats"]],
    )


def compare_hardening(
    base: HardeningReport, patched: HardeningReport
) -> list[HardeningDelta]:

    deltas: list[HardeningDelta] = []

    def add_bool(name: str, b: HardeningCheck, p: HardeningCheck) -> None:
        if b.enabled == p.enabled:
            return
        severity = (
            HARDENING_REGRESSION
            if b.enabled is True and p.enabled is not True
            else INFO
        )
        deltas.append(HardeningDelta(name, _fmt(b.enabled), _fmt(p.enabled), severity))

    add_bool("NX", base.nx, patched.nx)
    add_bool("PIE", base.pie, patched.pie)
    if base.relro != patched.relro:
        rank = {RELRO_NONE: 0, RELRO_PARTIAL: 1, RELRO_FULL: 2}
        severity = (
            HARDENING_REGRESSION if rank[patched.relro] < rank[base.relro] else INFO
        )
        deltas.append(HardeningDelta("RELRO", base.relro, patched.relro, severity))
    add_bool("Stack Canary", base.canary, patched.canary)
    return deltas


def _fmt(value: bool | None) -> str:
    if value is True:
        return "Enabled"
    if value is False:
        return "Disabled"
    return "Unknown"


def has_hardening_regression(deltas: list[HardeningDelta]) -> bool:
    return any(delta.severity == HARDENING_REGRESSION for delta in deltas)


def format_hardening_report(report: HardeningReport) -> str:

    lines = [
        f"Hardening: {report.binary_path}",
        f"  sha256: {report.sha256}",
        f"  NX:     {_fmt(report.nx.enabled)}  ({report.nx.evidence})",
        f"  PIE:    {_fmt(report.pie.enabled)}  ({report.pie.evidence})",
        f"  RELRO:  {report.relro}  ({report.relro_evidence})",
        f"  Canary: {_fmt(report.canary.enabled)}  ({report.canary.evidence})",
    ]
    for caveat in report.caveats:
        lines.append(f"  NOTE: {caveat}")
    return "\n".join(lines)
