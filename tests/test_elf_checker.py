from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hardening.elf_checker import (
    HARDENING_REGRESSION,
    INFO,
    RELRO_FULL,
    RELRO_NONE,
    RELRO_PARTIAL,
    HardeningError,
    _inspect_with_readelf,
    compare_hardening,
    inspect_elf,
)

C_SOURCE = r"""
#include <stdio.h>
int main(int argc, char **argv) {
    char buf[8];
    if (argc > 1) {
        snprintf(buf, sizeof buf, "%s", argv[1]);
        puts(buf);
    }
    return 0;
}
"""

VARIANTS = {
    "full": ["-O1", "-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,relro,-z,now"],
    "no_canary": [
        "-O1",
        "-fno-stack-protector",
        "-fPIE",
        "-pie",
        "-Wl,-z,relro,-z,now",
    ],
    "no_pie": [
        "-O1",
        "-fstack-protector-strong",
        "-fno-pie",
        "-no-pie",
        "-Wl,-z,relro,-z,now",
    ],
    "partial_relro": [
        "-O1",
        "-fstack-protector-strong",
        "-fPIE",
        "-pie",
        "-Wl,-z,relro,-z,lazy",
    ],
    "no_relro": ["-O1", "-fstack-protector-strong", "-fPIE", "-pie", "-Wl,-z,norelro"],
    "execstack": [
        "-O1",
        "-fstack-protector-strong",
        "-fPIE",
        "-pie",
        "-Wl,-z,relro,-z,now",
        "-Wl,-z,execstack",
    ],
}


@pytest.fixture(scope="module")
def fixtures_dir(tmp_path_factory) -> dict[str, Path]:
    build_dir = tmp_path_factory.mktemp("elf_fixtures")
    source = build_dir / "target.c"
    source.write_text(C_SOURCE)
    binaries: dict[str, Path] = {}
    for name, flags in VARIANTS.items():
        output = build_dir / name
        proc = subprocess.run(
            ["gcc", str(source), *flags, "-o", str(output)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"gcc {name} failed: {proc.stderr}"
        binaries[name] = output
    return binaries


class TestInspectElf:
    def test_full_hardening_profile(self, fixtures_dir):
        report = inspect_elf(fixtures_dir["full"])
        assert report.nx.enabled is True
        assert report.pie.enabled is True
        assert report.relro == RELRO_FULL
        assert report.canary.enabled is True
        assert len(report.sha256) == 64
        assert any("ASLR" in caveat for caveat in report.caveats)
        assert any("does not prove" in caveat for caveat in report.caveats)

    def test_no_canary_detected(self, fixtures_dir):
        assert inspect_elf(fixtures_dir["no_canary"]).canary.enabled is False

    def test_no_pie_detected(self, fixtures_dir):
        assert inspect_elf(fixtures_dir["no_pie"]).pie.enabled is False

    def test_partial_relro_detected(self, fixtures_dir):
        assert inspect_elf(fixtures_dir["partial_relro"]).relro == RELRO_PARTIAL

    def test_no_relro_detected(self, fixtures_dir):
        assert inspect_elf(fixtures_dir["no_relro"]).relro == RELRO_NONE

    def test_execstack_disables_nx(self, fixtures_dir):
        report = inspect_elf(fixtures_dir["execstack"])
        assert report.nx.enabled is False
        assert "E" in report.nx.evidence

    def test_rejects_non_elf_file(self, tmp_path):
        bogus = tmp_path / "not_elf"
        bogus.write_text("#!/bin/sh\necho hi\n")
        with pytest.raises(HardeningError, match="not an ELF"):
            inspect_elf(bogus)

    def test_rejects_missing_file(self, tmp_path):
        with pytest.raises(HardeningError, match="not found"):
            inspect_elf(tmp_path / "does_not_exist")


@pytest.fixture(scope="module")
def reports(fixtures_dir) -> dict[str, object]:
    return {name: inspect_elf(path) for name, path in fixtures_dir.items()}


class TestCompareHardening:
    @pytest.mark.parametrize(
        "variant,protection",
        [
            ("no_canary", "Stack Canary"),
            ("execstack", "NX"),
            ("no_pie", "PIE"),
            ("partial_relro", "RELRO"),
            ("no_relro", "RELRO"),
        ],
    )
    def test_downgrade_is_flagged(self, reports, variant, protection):
        deltas = compare_hardening(reports["full"], reports[variant])
        assert any(
            d.protection == protection and d.severity == HARDENING_REGRESSION
            for d in deltas
        )

    def test_upgrade_is_info_not_regression(self, reports):
        deltas = compare_hardening(reports["no_canary"], reports["full"])
        canary_delta = next(d for d in deltas if d.protection == "Stack Canary")
        assert canary_delta.severity == INFO

    def test_identical_profiles_produce_no_deltas(self, reports):
        assert compare_hardening(reports["full"], reports["full"]) == []


@pytest.fixture(scope="module")
def flags_bind_now_fixture(tmp_path_factory) -> Path:

    import io
    import struct

    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile

    DT_FLAGS = 30
    DT_FLAGS_1 = 0x6FFFFFFB
    DF_BIND_NOW = 0x8

    build_dir = tmp_path_factory.mktemp("elf_flags_fixture")
    source = build_dir / "target.c"
    source.write_text(C_SOURCE)
    binary = build_dir / "dt_flags_bind_now"
    proc = subprocess.run(
        [
            "gcc",
            str(source),
            "-O1",
            "-fstack-protector-strong",
            "-fPIE",
            "-pie",
            "-Wl,-z,relro,-z,now",
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"gcc failed: {proc.stderr}"

    data = bytearray(binary.read_bytes())
    elf = ELFFile(io.BytesIO(data))
    assert not any(
        tag["d_tag"] in ("DT_BIND_NOW", 24)
        for section in elf.iter_sections()
        if isinstance(section, DynamicSection)
        for tag in section.iter_tags()
    ), "fixture premise: modern ld must not emit a DT_BIND_NOW tag"
    replaced = False
    for section in elf.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for index, tag in enumerate(section.iter_tags()):
            if tag["d_tag"] in ("DT_FLAGS_1", DT_FLAGS_1):
                offset = section["sh_offset"] + index * 16
                struct.pack_into("<Q", data, offset, DT_FLAGS)
                struct.pack_into("<Q", data, offset + 8, DF_BIND_NOW)
                replaced = True
                break
        if replaced:
            break
    assert replaced, "DT_FLAGS_1 not found in fixture binary"
    binary.write_bytes(data)
    return binary


class TestDtFlagsBindNow:
    def test_pyelftools_path_reports_full_relro(self, flags_bind_now_fixture):
        report = inspect_elf(flags_bind_now_fixture)
        assert report.relro == RELRO_FULL
        assert "DF_BIND_NOW in DT_FLAGS" in report.relro_evidence

    def test_readelf_path_reports_full_relro(self, flags_bind_now_fixture):
        fallback = _inspect_with_readelf(flags_bind_now_fixture)
        assert fallback.relro == RELRO_FULL
        assert "DF_BIND_NOW" in fallback.relro_evidence

    def test_equivalent_representations_do_not_false_downgrade(
        self, fixtures_dir, flags_bind_now_fixture
    ):

        regular = inspect_elf(fixtures_dir["full"])
        patched = inspect_elf(flags_bind_now_fixture)
        assert regular.relro == RELRO_FULL
        deltas = compare_hardening(regular, patched)
        assert not any(d.protection == "RELRO" for d in deltas)


class TestReadelfFallback:
    def test_fallback_matches_pyelftools(self, fixtures_dir):
        primary = inspect_elf(fixtures_dir["full"])
        fallback = _inspect_with_readelf(fixtures_dir["full"])
        assert (
            primary.nx.enabled,
            primary.pie.enabled,
            primary.relro,
            primary.canary.enabled,
        ) == (
            fallback.nx.enabled,
            fallback.pie.enabled,
            fallback.relro,
            fallback.canary.enabled,
        )


def without_section_headers(source: Path, destination: Path) -> Path:

    import struct

    data = bytearray(source.read_bytes())
    assert data[4:6] == b"\x02\x01"
    struct.pack_into("<Q", data, 40, 0)
    struct.pack_into("<HHH", data, 58, 0, 0, 0)
    destination.write_bytes(data)
    destination.chmod(0o755)
    return destination


@pytest.mark.parametrize(
    "variant", ["full", "partial_relro", "no_pie", "no_relro", "no_canary"]
)
def test_sectionless_runtime_hardening_matches_original(
    fixtures_dir, tmp_path, variant
):
    original = inspect_elf(fixtures_dir[variant])
    binary = without_section_headers(fixtures_dir[variant], tmp_path / "sectionless")
    assert subprocess.run([str(binary)], capture_output=True, timeout=5).returncode == 0
    primary = inspect_elf(binary)
    fallback = _inspect_with_readelf(binary)
    assert (
        primary.nx.enabled,
        primary.pie.enabled,
        primary.relro,
        primary.canary.enabled,
    ) == (
        original.nx.enabled,
        original.pie.enabled,
        original.relro,
        original.canary.enabled,
    )
    assert (primary.nx.enabled, primary.pie.enabled, primary.relro) == (
        fallback.nx.enabled,
        fallback.pie.enabled,
        fallback.relro,
    )
    assert compare_hardening(original, primary) == []
    if original.canary.enabled:
        assert "PT_DYNAMIC" in primary.canary.evidence


def test_sectionless_dt_flags_bind_now(flags_bind_now_fixture, tmp_path):
    binary = without_section_headers(flags_bind_now_fixture, tmp_path / "flags-only")
    assert inspect_elf(binary).relro == RELRO_FULL
    assert _inspect_with_readelf(binary).relro == RELRO_FULL
