"""Patch Manatan 6.2.13 ARM64 PhotoView hit testing without executing the app."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

INPUT_SHA = "7ea743dbf674ad42650030fec40aba9dcfe95bd0f4dfdd482f7fbc4410e3be9d"
OUTPUT_SHA = "2d5ac822b46902139c592e67a01163492467f12403963189f7107fd3a3f4ccbf"
APK_ENTRY = "lib/arm64-v8a/libapp.so"
PATCH = 0xAB22A0
NORMAL = 0xAB22A4
REJECT = 0xAB2338
EXPECTED_INSTRUCTION = bytes.fromhex("c0042037")  # tbnz w0, #4, 0xab2338
PAGE = 0x4000


def sha(data):
    return hashlib.sha256(data).hexdigest()


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def elf(data):
    return ELFFile(io.BytesIO(data))


def offset_for(binary, va):
    segments = [s for s in binary.iter_segments() if s["p_type"] == "PT_LOAD"
                and s["p_vaddr"] <= va < s["p_vaddr"] + s["p_filesz"]]
    if len(segments) != 1:
        raise ValueError(f"Expected one file mapping at {va:#x}")
    segment = segments[0]
    return segment["p_offset"] + va - segment["p_vaddr"]


def assembly(stub_va):
    # x0, x4, x17 are dead at NORMAL: the original sequence reloads them before
    # reading them. REJECT restores x0 to false and returns. No call or GC occurs.
    source = f"""
        tbz w0, #4, allow
        ldur x4, [x29, #-8]
        ldur w0, [x4, #-1]
        ubfx w0, w0, #12, #20
        mov w17, #6400
        cmp w0, w17
        b.ne reject
        ldur w0, [x4, #0x53]
        tbz w0, #0, reject
        cmp w0, w22
        b.eq reject
        add x0, x0, x28, lsl #32
        ldur w0, [x0, #-1]
        ubfx w0, w0, #12, #20
        mov w17, #3813
        cmp w0, w17
        b.ne reject
    allow:
        b {NORMAL:#x}
    reject:
        b {REJECT:#x}
    """
    assembler = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    encoded, _ = assembler.asm(source, addr=stub_va)
    branch, _ = assembler.asm(f"b {stub_va:#x}", addr=PATCH)
    if len(branch) != 4:
        raise ValueError("Patch must be one four-byte ARM64 instruction")
    return bytes(encoded), bytes(branch), source.strip()


def disassembly(data, va):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    instructions = list(decoder.disasm(data, va))
    if sum(i.size for i in instructions) != len(data):
        raise ValueError("Instruction decode did not cover complete patch")
    return [f"{i.address:08x}: {i.bytes.hex()}  {i.mnemonic} {i.op_str}" for i in instructions]


def emulate(stub, branch, stub_va):
    cases = []
    # Exercise ordinary CIDs broadly, the exact target and both adjacent CIDs;
    # delegate cases cover valid target, other type, Smi and null.
    checks = [(inside, cid, dcid, None) for inside in (False, True)
              for cid in (1, 63, 100, 3813, 6399, 6400, 6401, 6427, 6428, 65535, 1048575)
              for dcid in (1, 3812, 3813, 3814)]
    checks += [(False, 6400, 0, "smi"), (False, 6400, 0, "null")]
    preserved = [UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X5,
                 UC_ARM64_REG_X15, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X26,
                 UC_ARM64_REG_X27, UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30,
                 UC_ARM64_REG_SP]
    for inside, cid, dcid, invalid_delegate in checks:
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(PATCH & ~0xFFF, 0x1000)
        cpu.mem_write(PATCH, branch)
        cpu.mem_map(stub_va & ~0xFFF, 0x1000)
        cpu.mem_write(stub_va, stub)
        stack = 0x50000000
        heap = 0x7000200000
        cpu.mem_map(stack, 0x1000)
        cpu.mem_map(heap, 0x10000)
        frame = stack + 0x800
        box, delegate, null = heap + 0x101, heap + 0x401, heap + 0x81
        cpu.mem_write(frame - 8, struct.pack("<Q", box))
        cpu.mem_write(box - 1, struct.pack("<I", cid << 12))
        compressed = 0x10 if invalid_delegate == "smi" else null & 0xFFFFFFFF if invalid_delegate == "null" else delegate & 0xFFFFFFFF
        cpu.mem_write(box + 0x53, struct.pack("<I", compressed))
        cpu.mem_write(delegate - 1, struct.pack("<I", dcid << 12))
        for index, register in enumerate(preserved):
            cpu.reg_write(register, 0x8000 + index * 0x100)
        cpu.reg_write(UC_ARM64_REG_X22, null)
        cpu.reg_write(UC_ARM64_REG_X28, heap >> 32)
        cpu.reg_write(UC_ARM64_REG_X29, frame)
        cpu.reg_write(UC_ARM64_REG_X0, null + (0x20 if inside else 0x30))
        before = {r: cpu.reg_read(r) for r in preserved}
        arrived = []
        def stop_at_original(cpu, address, size, unused):
            if address in (NORMAL, REJECT):
                arrived.append(address)
                cpu.emu_stop()
        cpu.hook_add(UC_HOOK_CODE, stop_at_original)
        cpu.emu_start(PATCH, 0, count=40)
        expected = NORMAL if inside or (cid == 6400 and dcid == 3813 and invalid_delegate is None) else REJECT
        if arrived != [expected]:
            raise ValueError(f"Wrong branch for {inside,cid,dcid,invalid_delegate}: {arrived}")
        if any(cpu.reg_read(r) != value for r, value in before.items()):
            raise ValueError("Trampoline modified a live/preserved register")
        if cpu.mem_read(frame - 8, 8) != struct.pack("<Q", box):
            raise ValueError("Trampoline changed the stack")
        cases.append({"contains": inside, "box_cid": cid, "delegate_cid": dcid,
                      "invalid_delegate": invalid_delegate, "destination": hex(expected), "passed": True})
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--input-lib", type=Path, help="Original ARM64 libapp.so")
    inputs.add_argument("--input-apk", type=Path, help="Extract the original ARM64 library from a local APK")
    inputs.add_argument("--self-test", action="store_true", help="Run the 90 ARM64 guard tests without an APK")
    parser.add_argument("--output-lib", type=Path, help="Patched ELF output; required unless --self-test")
    args = parser.parse_args()
    if args.self_test:
        stub, branch, _ = assembly(0x17A41C0)
        print(json.dumps({"arm64_cases_passed": len(emulate(stub, branch, 0x17A41C0))}))
        return
    if args.output_lib is None:
        parser.error("--output-lib is required when patching an input")
    source_path = (args.input_lib or args.input_apk).resolve()
    output_path = args.output_lib.resolve()
    if source_path == output_path:
        parser.error("The output must differ from the original input")
    if args.input_apk:
        with zipfile.ZipFile(source_path) as archive:
            original = archive.read(APK_ENTRY)
    else:
        original = source_path.read_bytes()
    if sha(original) != INPUT_SHA:
        raise ValueError("Exact Manatan 6.2.13 ARM64 libapp.so SHA-256 required")
    old = elf(original)
    if old["e_machine"] != "EM_AARCH64" or old.elfclass != 64 or not old.little_endian:
        raise ValueError("Unexpected ELF architecture or encoding")
    if old["e_phentsize"] != 56:
        raise ValueError("Unexpected ELF64 program-header layout")
    patch_offset = offset_for(old, PATCH)
    if original[patch_offset:patch_offset + 4] != EXPECTED_INSTRUCTION:
        raise ValueError("Original branch bytes mismatch")
    append_offset = align(len(original), PAGE)
    load_end = max(s["p_vaddr"] + s["p_memsz"] for s in old.iter_segments() if s["p_type"] == "PT_LOAD")
    append_va = align(load_end, PAGE)
    count = old["e_phnum"] + 1
    table_size = count * 56
    stub_offset = align(table_size, 16)
    stub_va = append_va + stub_offset
    stub, branch, source = assembly(stub_va)
    segment_size = align(stub_offset + len(stub), PAGE)
    page = bytearray(segment_size)
    phdr_count = 0
    for index, segment in enumerate(old.iter_segments()):
        entry = bytearray(original[old["e_phoff"] + index * 56:old["e_phoff"] + (index + 1) * 56])
        if segment["p_type"] == "PT_PHDR":
            entry = struct.pack("<IIQQQQQQ", 6, 4, append_offset, append_va, append_va, table_size, table_size, 8)
            phdr_count += 1
        page[index * 56:(index + 1) * 56] = entry
    if phdr_count != 1:
        raise ValueError("Expected exactly one original PT_PHDR")
    # A separate RX page keeps the program table and tiny stub away from all
    # original data/code and satisfies 16-KiB page alignment.
    page[(count - 1) * 56:count * 56] = struct.pack("<IIQQQQQQ", 1, 5, append_offset, append_va, append_va,
                                                              segment_size, segment_size, PAGE)
    page[stub_offset:stub_offset + len(stub)] = stub
    patched = bytearray(original)
    patched.extend(b"\0" * (append_offset - len(patched)))
    patched.extend(page)
    struct.pack_into("<Q", patched, 32, append_offset)
    struct.pack_into("<H", patched, 56, count)
    patched[patch_offset:patch_offset + 4] = branch
    changed = [i for i, (a, b) in enumerate(zip(original, patched)) if a != b]
    allowed = set(range(32, 40)) | set(range(56, 58)) | set(range(patch_offset, patch_offset + 4))
    if not set(changed) <= allowed:
        raise ValueError("Unexpected change to original file bytes")
    check = elf(patched)
    for section in old.iter_sections():
        if not section.name:
            continue
        actual = check.get_section_by_name(section.name)
        if actual is None or dict(actual.header) != dict(section.header):
            raise ValueError(f"Original section metadata changed: {section.name}")
        expected = bytearray(section.data())
        if section["sh_addr"] <= PATCH < section["sh_addr"] + section["sh_size"] and section["sh_flags"] & 2:
            at = PATCH - section["sh_addr"]
            expected[at:at + 4] = branch
        if actual.data() != expected:
            raise ValueError(f"Unexpected original section content change: {section.name}")
    new_segments = list(check.iter_segments())
    if new_segments[-1]["p_type"] != "PT_LOAD" or new_segments[-1]["p_flags"] != 5:
        raise ValueError("Appended segment must be read-execute only")
    if offset_for(check, stub_va) != append_offset + stub_offset:
        raise ValueError("Trampoline mapping mismatch")
    phdr = next(s for s in check.iter_segments() if s["p_type"] == "PT_PHDR")
    if phdr["p_offset"] != check["e_phoff"] or phdr["p_filesz"] != check["e_phnum"] * 56:
        raise ValueError("Relocated PT_PHDR does not describe the new table")
    needed = [t.needed for t in check.get_section_by_name(".dynamic").iter_tags() if t.entry.d_tag == "DT_NEEDED"]
    if needed:
        raise ValueError("Permanent patch must not depend on Gadget or another new library")
    cases = emulate(stub, branch, stub_va)
    if sha(patched) != OUTPUT_SHA:
        raise ValueError("Patched ELF digest differs from the reviewed result")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(patched)
    dump = "\n".join(disassembly(branch, PATCH) + [""] + disassembly(stub, stub_va)) + "\n"
    output_path.with_suffix(".trampoline.asm").write_text(source + "\n", encoding="ascii")
    output_path.with_suffix(".disassembly.txt").write_text(dump, encoding="ascii")
    output_path.with_suffix(".emulator-cases.json").write_text(json.dumps(cases, indent=2) + "\n", encoding="utf-8")
    report = {
        "input": str(source_path), "input_sha256": INPUT_SHA, "output": str(output_path),
        "output_sha256": sha(patched), "output_bytes": len(patched),
        "patch_va": hex(PATCH), "original_instruction": EXPECTED_INSTRUCTION.hex(), "patch_instruction": branch.hex(),
        "allow_destination": hex(NORMAL), "reject_destination": hex(REJECT), "stub_va": hex(stub_va),
        "stub_bytes": len(stub), "rx_segment_va": hex(append_va), "rx_segment_file_offset": hex(append_offset),
        "rx_segment_bytes": segment_size, "rx_segment_flags": "R-X", "new_program_header_count": count,
        "changed_original_byte_offsets": [hex(i) for i in changed], "original_sections_and_addresses_preserved": True,
        "original_section_byte_changes": {".text": "one four-byte branch instruction"},
        "added_dependencies": needed, "emulator_cases_passed": len(cases),
        "registers_written": ["x0", "x4", "x17", "NZCV", "PC"],
        "register_liveness": "Normal path immediately reloads x4/x0/x17 before next reads; reject path restores x0=false and returns; NZCV is not read before a subsequent call. No stack writes, calls, allocations, or GC.",
        "runtime_status": "This tool does not install or execute the app. See README for recorded device validation and its limits."
    }
    output_path.with_suffix(".report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("output", "output_sha256", "patch_va", "stub_va", "stub_bytes", "emulator_cases_passed")}, indent=2))


if __name__ == "__main__":
    main()
