#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Create a CrossOver variant of the supplied 1.6 Windows runtime.

This is a temporary binary equivalent of selecting a higher USER_MIN, until the
source allocator fallback is rebuilt. Only the known input is accepted. Each
instruction was checked against the executable's COFF symbols/disassembly.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

INPUT_SHA256 = "4ae2d15eafce351c61dc10b8498b2bad61cdc3a5c15c92e274fd63a7a4fc312a"
USER_MIN = 0x1000000000
USER_MAX = 0xFC00000000
COMPAT_MIN = 0x7000000000
# File offsets of imm64 operands in .text, with their preceding opcode.
PATCHES = (
    (0xB4DF, b"\x48\xbf", USER_MAX - USER_MIN, USER_MAX - COMPAT_MIN,
     "runtime_memory_reserve: reservation size"),
    (0xB4E9, b"\x48\xbe", USER_MIN, COMPAT_MIN,
     "runtime_memory_reserve: reservation and region start"),
    (0xC01B, b"\x49\xbe", USER_MIN + 1, COMPAT_MIN + 1,
     "runtime_low_map: upper limit"),
    (0xD3D6, b"\x48\xb9", USER_MIN, COMPAT_MIN,
     "place/find_free: first-fit lower limit"),
    (0x1B6CF, b"\x48\xb8", USER_MIN, COMPAT_MIN,
     "Core::AddressSpace::GetUsableRegions: GPU lower limit"),
)
OVERLAY_TRANSLATIONS = Path(__file__).with_name("resources") / "overlay_translations.json"


def patch_overlay_text(data: bytearray) -> int:
    """Translate the pinned renderer's Russian C strings without changing PE layout."""
    translations = json.loads(OVERLAY_TRANSLATIONS.read_text(encoding="utf-8"))
    replaced = 0
    for source, target in translations.items():
        source_bytes = source.encode("utf-8")
        target_bytes = target.encode("utf-8")
        if len(target_bytes) > len(source_bytes):
            raise ValueError(f"English overlay text is too long for its pinned slot: {source!r}")
        positions = []
        cursor = 0
        while True:
            offset = data.find(source_bytes, cursor)
            if offset < 0:
                break
            end = offset + len(source_bytes)
            if (offset == 0 or data[offset - 1] == 0) and (end == len(data) or data[end] == 0):
                positions.append(offset)
            cursor = offset + 1
        if not positions:
            raise ValueError(f"Pinned renderer is missing overlay text: {source!r}")
        translated = target_bytes + bytes(len(source_bytes) - len(target_bytes))
        for offset in reversed(positions):
            data[offset:offset + len(source_bytes)] = translated
        replaced += len(positions)
    return replaced


def add_bootstrap_import(data: bytearray) -> None:
    """Prepend one import without relocating any original imports/code/data."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe + 4
    sections = struct.unpack_from("<H", data, coff + 2)[0]
    optional = coff + 20
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    if struct.unpack_from("<H", data, optional)[0] != 0x20B:
        raise ValueError("Expected PE32+ optional header")
    section_alignment, file_alignment = struct.unpack_from("<II", data, optional + 32)
    table = optional + optional_size
    new_header = table + sections * 40
    size_headers = struct.unpack_from("<I", data, optional + 60)[0]
    if new_header + 40 > size_headers or any(data[new_header:new_header + 40]):
        raise ValueError("No space for bootstrap section header")
    layouts = []
    for index in range(sections):
        header = table + index * 40
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, header + 8)
        layouts.append((rva, max(virtual_size, raw_size), raw_offset))

    def offset_of(rva):
        for start, size, offset in layouts:
            if start <= rva < start + size:
                return offset + rva - start
        raise ValueError("Import descriptor is outside the original sections")

    directory = optional + 112 + 8  # IMAGE_DIRECTORY_ENTRY_IMPORT
    import_rva, _ = struct.unpack_from("<II", data, directory)
    descriptors = []
    original_offset = offset_of(import_rva)
    while any(data[original_offset:original_offset + 20]):
        descriptors.append(bytes(data[original_offset:original_offset + 20]))
        original_offset += 20
    align = lambda value, boundary: (value + boundary - 1) // boundary * boundary
    section_rva = align(max(start + size for start, size, _ in layouts), section_alignment)
    raw_offset = align(len(data), file_alignment)
    descriptor_size = (len(descriptors) + 2) * 20
    lookup_offset = align(descriptor_size, 8)
    iat_offset = lookup_offset + 16
    dll_offset = iat_offset + 16
    dll_name = b"bb-crossover-bootstrap.dll\0"
    symbol_offset = align(dll_offset + len(dll_name), 2)
    symbol = b"\0\0bb_crossover_patch_tcb\0"
    code_offset = align(symbol_offset + len(symbol), 16)
    section = bytearray(code_offset + 35)
    struct.pack_into("<IIIII", section, 0, section_rva + lookup_offset, 0, 0,
                     section_rva + dll_offset, section_rva + iat_offset)
    for index, descriptor in enumerate(descriptors, start=1):
        section[index * 20:(index + 1) * 20] = descriptor
    struct.pack_into("<Q", section, lookup_offset, section_rva + symbol_offset)
    struct.pack_into("<Q", section, iat_offset, section_rva + symbol_offset)
    section[dll_offset:dll_offset + len(dll_name)] = dll_name
    section[symbol_offset:symbol_offset + len(symbol)] = symbol
    # main's inlined patch_tcb_loads is replaced with a call to the adapter.
    code_rva = section_rva + code_offset
    code = bytearray(b"\x48\x8b\x8d\x60\x11\x00\x00"   # rcx = segments
                     b"\x48\x8b\x95\x80\x11\x00\x00"   # rdx = count
                     b"\x4c\x8b\x05" + struct.pack("<i", 0xC0CC88 - (code_rva + 21)) +
                     b"\xff\x15" + struct.pack("<i", section_rva + iat_offset - (code_rva + 27)) +
                     b"\x48\x89\xc2" +                    # rdx = patched count
                     b"\xe9" + struct.pack("<i", 0x3136 - (code_rva + 35)))
    section[code_offset:] = code
    call_site = 0x2521  # RVA 0x3121
    expected_call = b"\xe8\x3a\x4e\x01\x00"
    if data[call_site:call_site + 5] != expected_call:
        raise ValueError("Unexpected inline TCB patch entry")
    data[call_site:call_site + 5] = b"\xe9" + struct.pack("<i", code_rva - 0x3126)
    if data[0x17384:0x17386] != b"\x73\x0d":
        raise ValueError("Unexpected TLS slot guard")
    # TlsSetValue handles expansion slots; the adapter provides the guest loads.
    data[0x17384:0x17386] = b"\x90\x90"
    virtual_size = len(section)
    raw_size = align(virtual_size, file_alignment)
    header = struct.pack("<8sIIIIIIHHI", b".bbmac\0\0", virtual_size, section_rva,
                         raw_size, raw_offset, 0, 0, 0, 0, 0xE0000060)
    data[new_header:new_header + 40] = header
    struct.pack_into("<H", data, coff + 2, sections + 1)
    struct.pack_into("<I", data, optional + 56, align(section_rva + virtual_size, section_alignment))
    struct.pack_into("<II", data, directory, section_rva, descriptor_size)
    struct.pack_into("<I", data, optional + 64, 0)  # Optional PE checksum, changed image.
    data.extend(bytes(raw_offset - len(data)))
    data.extend(section)
    data.extend(bytes(raw_size - virtual_size))


def patch(source: Path, destination: Path) -> Path:
    data = bytearray(source.read_bytes())
    if hashlib.sha256(data).hexdigest() != INPUT_SHA256:
        raise ValueError("Unsupported runtime version; refusing to patch unknown code.")
    patch_overlay_text(data)
    for offset, opcode, old, new, label in PATCHES:
        expected = opcode + struct.pack("<Q", old)
        if data[offset - 2:offset + 8] != expected:
            raise ValueError(f"Instruction differs: {label}")
        data[offset:offset + 8] = struct.pack("<Q", new)
    # tls_slot in .data, corresponding to RVA 0xc052d8.
    if data[0xC02AD8:0xC02ADC] != b"\xff" * 4:
        raise ValueError("Guest TLS slot variable differs")
    add_bootstrap_import(data)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists() or destination.read_bytes() != data:
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_bytes(data)
        temporary.replace(destination)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(patch(args.source, args.destination))
