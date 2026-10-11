import hashlib
import math
import re
import struct
from functools import lru_cache

lazy import capstone as cs
lazy from capstone import x86

from .sources import ADDRESS_LIMIT, PE, integer

FORMATS = {
    "u8": "B",
    "i8": "b",
    "u16": "H",
    "i16": "h",
    "u32": "I",
    "i32": "i",
    "u64": "Q",
    "i64": "q",
    "f32": "f",
    "f64": "d",
    "pointer": "Q",
}
MAX_DECODE_BYTES = 1 << 20
IGNORED_SEGMENT = re.compile(r"\b[cdes]s:")


def decoder():
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    return md


def limited(rows, limit):
    saved, total = [], 0
    for row in rows:
        total += 1
        if len(saved) < limit:
            saved.append(row)
    return {"results": saved, "total": total, "truncated": total > limit}


def pattern_bytes(text):
    tokens = text.split()
    if not tokens or any(not re.fullmatch(r"[0-9a-fA-F]{2}|\?\?", token) for token in tokens):
        raise ValueError("Patterns use space-separated byte pairs and ?? wildcards")
    if all(token == "??" for token in tokens):
        raise ValueError("A byte pattern must contain at least one exact byte")
    return b"".join(b"." if token == "??" else re.escape(bytes.fromhex(token)) for token in tokens)


def occurrences(data, needle, start=0, end=None):
    end = len(data) if end is None else end
    while (start := data.find(needle, start, end)) >= 0:
        yield start
        start += 1


def search(
    source, *, text=None, encoding="ascii", pattern=None, value=None, value_type="u32", limit=100, scope=None
):
    queries = []
    if text is not None:
        if not text:
            raise ValueError("Search text must not be empty")
        for codec in ["ascii", "utf-16le"] if encoding == "both" else [encoding]:
            try:
                raw = text.encode(codec)
            except UnicodeEncodeError:
                if encoding == "both" and codec == "ascii":
                    continue
                raise ValueError(f"Text cannot be encoded as {codec}") from None
            queries.append((codec, re.escape(raw)))
    elif pattern is not None:
        queries.append(("pattern", pattern_bytes(pattern)))
    else:
        number = float(value) if value_type.startswith("f") else integer(value, signed=True)
        queries.append((value_type, re.escape(struct.pack("<" + FORMATS[value_type], number))))
    spans = source.spans(**(scope or {}))
    rows, total = [], 0
    for kind, expression in queries:
        matcher = re.compile(b"(?=(" + expression + b"))", re.DOTALL)
        for start, end in spans:
            for match in matcher.finditer(source.data, start, end):
                total += 1
                if len(rows) < limit:
                    rows.append({**source.location(match.start()), "kind": kind, "bytes_hex": match[1].hex()})
    return {
        "results": rows,
        "total": total,
        "truncated": total > limit,
        "scan_bytes": sum(b - a for a, b in spans),
    }


def describe_va(source, va):
    row = {"va": hex(va)}
    if source.base is not None and source.base <= va < source.base + source.image_size:
        row["rva"] = hex(va - source.base)
    if va in source.imports:
        row["import"] = source.imports[va]
    try:
        offset = source.offset_of_va(va)
    except ValueError:
        row["available"] = False
        return row
    row.update(source.location(offset), available=True)
    region = source.region_at(va)
    raw = source.data[offset : offset + min(160, region.va + region.size - va)]
    for pattern, codec in (
        (rb"([\x20-\x7e]{3,})\x00", "ascii"),
        (rb"((?:[\x20-\x7e]\x00){3,})\x00\x00", "utf-16le"),
    ):
        match = re.prefixmatch(pattern, raw)
        if match:
            row["string"] = {"encoding": codec, "text": match[1].decode(codec)}
            break
    return row


def instruction_refs(ins):
    branch = ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_BRANCH_RELATIVE)
    for operand in ins.operands:
        if branch and operand.type == x86.X86_OP_IMM:
            yield ("call" if ins.group(cs.CS_GRP_CALL) else "branch"), operand.imm % ADDRESS_LIMIT
        if operand.type != x86.X86_OP_MEM:
            continue
        memory = operand.mem
        if memory.segment in (x86.X86_REG_FS, x86.X86_REG_GS) or memory.index:
            continue
        if memory.base == x86.X86_REG_RIP:
            yield "memory", (ins.address + ins.size + memory.disp) % ADDRESS_LIMIT
        elif memory.base == x86.X86_REG_EIP:
            yield "memory", (ins.address + ins.size + memory.disp) % (1 << 32)
        elif not memory.base:
            yield "memory", memory.disp % (1 << (ins.addr_size * 8))


def instruction_row(source, ins, *, include_references=True):
    row = {
        "va": hex(ins.address),
        "size": ins.size,
        "bytes_hex": ins.bytes.hex(),
        "mnemonic": ins.mnemonic,
        "operands": ins.op_str,
    }
    if source.base is not None and source.base <= ins.address < source.base + source.image_size:
        row["rva"] = hex(ins.address - source.base)
    refs = list(instruction_refs(ins))
    if refs and include_references:
        row["references"] = [{"kind": kind, **describe_va(source, va)} for kind, va in refs]
    if (ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP)) and not any(
        kind in ("call", "branch") for kind, _ in refs
    ):
        row["indirect_control_flow"] = "memory_cell" if refs else "unresolved"
    return row


def disassemble(source, address, *, byte_count=None, unwind=False, limit=100):
    va = source.va(address)
    region = None
    if unwind:
        if not isinstance(source, PE):
            raise ValueError("--unwind requires a PE file")
        region = source.unwind_region(va)
        va = source.base + region["begin_rva"]
        byte_count = region["end_rva"] - region["begin_rva"]
    if byte_count is None:
        backing = source.region_at(va)
        byte_count = min(256, backing.va + backing.size - va)
    if not 0 < byte_count <= MAX_DECODE_BYTES:
        raise ValueError(f"Disassembly ranges must be 1..{MAX_DECODE_BYTES} bytes")
    raw = source.read(va, byte_count)
    rows, end = [], va
    reason = "range_end"
    for ins in decoder().disasm(raw, va, count=limit + 1):
        if len(rows) == limit:
            reason = "output_limit"
            break
        rows.append(instruction_row(source, ins))
        end = ins.address + ins.size
    if reason != "output_limit" and end < va + byte_count:
        reason = "invalid_or_truncated_instruction"
    return {
        "origin_va": hex(va),
        "unwind_region": {
            "begin_rva": hex(region["begin_rva"]),
            "end_rva": hex(region["end_rva"]),
            "chain": [{key: hex(value) for key, value in entry.items()} for entry in region["chain"]],
            "contiguous_entries": region["contiguous_entries"],
        }
        if region is not None
        else None,
        "byte_count": byte_count,
        "range_sha256": hashlib.sha256(raw).hexdigest(),
        "instructions": rows,
        "decoded_bytes": end - va,
        "remaining_bytes": va + byte_count - end,
        "stop_reason": reason,
    }


def read_data(source, address, value_type, count):
    fmt = "<" + FORMATS[value_type]
    width = struct.calcsize(fmt)
    if not 1 <= count <= 4096:
        raise ValueError("Data count must be 1..4096")
    offset = source.offset(address, width * count)
    raw = source.data[offset : offset + width * count]
    rows = []
    for index, (value,) in enumerate(struct.iter_unpack(fmt, raw)):
        row = {**source.location(offset + index * width), "value": value}
        if isinstance(value, float) and not math.isfinite(value):
            row["value"] = str(value)
        if value_type == "pointer":
            row["target"] = describe_va(source, value)
        rows.append(row)
    return {"type": value_type, "width": width, "bytes_hex": raw.hex(), "results": rows}


def redundant_prefix(earlier, later):
    # LOOP's implicit counter width is not shown in its operand text.
    if later.id in (x86.X86_INS_LOOP, x86.X86_INS_LOOPE, x86.X86_INS_LOOPNE):
        if earlier.addr_size != later.addr_size:
            return False
    # Retain REX on ModR/M forms, including MSVC's 48 FF 15/25 encodings.
    return (
        earlier.mnemonic == later.mnemonic
        and IGNORED_SEGMENT.sub("", earlier.op_str) == IGNORED_SEGMENT.sub("", later.op_str)
        and (earlier.rex == later.rex or not later.modrm_offset)
    )


class ReferenceScanner:
    def __init__(self, source):
        self.source = source
        self.md = decoder()
        self.lite = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)

    @lru_cache(maxsize=128)
    def boundaries(self, entry):
        begin, end, _ = entry
        if end - begin > MAX_DECODE_BYTES:
            return {}, self.source.base + begin, "candidate_verification_limit"
        raw = self.source.read(self.source.base + begin, end - begin)
        sizes = {va: size for va, size, _, _ in self.lite.disasm_lite(raw, self.source.base + begin)}
        stop = max((va + size for va, size in sizes.items()), default=self.source.base + begin)
        return sizes, stop, "candidate_after_decode_gap"

    def boundary(self, va):
        owner = self.source.owner(va)
        if owner is None:
            return "candidate_no_unwind"
        sizes, end, reason = self.boundaries(owner)
        if va in sizes:
            return "unwind_linear"
        return reason if va >= end else None

    def around(self, field, width, encoding_field, low, high):
        owner = self.source.owner(self.source.va_of_offset(field))
        if owner:
            low = max(low, self.source.offset_of_va(self.source.base + owner[0]))
        for start in range(max(low, field - 14), field):
            va = self.source.va_of_offset(start)
            boundary = self.boundary(va)
            if boundary is None:
                continue
            ins = next(self.md.disasm(self.source.data[start : min(high, start + 15)], va, count=1), None)
            if ins is None:
                continue
            if (
                start + getattr(ins, encoding_field + "_offset") != field
                or getattr(ins, encoding_field + "_size") != width
            ):
                continue
            owner = self.source.owner(va)
            if owner and va + ins.size > self.source.base + owner[1]:
                continue
            yield ins, boundary

    def code(self, target, kind, displacement, spans):
        data = self.source.data
        seen = set()
        for low, high in spans:
            start_va = self.source.va_of_offset(low)
            fields = self.fields(data, low, high, start_va, target, kind, displacement)
            for field, width, encoding_field in fields:
                candidates = {}
                for ins, boundary in self.around(field, width, encoding_field, low, high):
                    if displacement is not None:
                        matches = (
                            [("displacement", displacement)]
                            if any(
                                op.type == x86.X86_OP_MEM and op.mem.disp == displacement
                                for op in ins.operands
                            )
                            else []
                        )
                    else:
                        matches = [
                            (ref_kind, va)
                            for ref_kind, va in instruction_refs(ins)
                            if va == target and (kind == "all" or ref_kind == kind)
                        ]
                    for ref_kind, _ in matches:
                        candidates.setdefault(ref_kind, []).append((ins, boundary))
                for ref_kind, found in candidates.items():
                    key = (field, ref_kind)
                    if key in seen:
                        continue
                    seen.add(key)
                    ins, boundary = found[-1]
                    # shortcut: prefix selection is heuristic, use a known boundary for exact starts.
                    for earlier, earlier_boundary in reversed(found[:-1]):
                        if redundant_prefix(earlier, ins):
                            break
                        ins, boundary = earlier, earlier_boundary
                    row = instruction_row(self.source, ins, include_references=target is None)
                    row.update(kind=ref_kind, boundary=boundary)
                    owner = self.source.owner(ins.address)
                    if owner:
                        row["unwind_begin_rva"], row["unwind_end_rva"] = hex(owner[0]), hex(owner[1])
                    yield row

    @staticmethod
    def fields(data, low, high, start_va, target, kind, displacement):
        if displacement is not None:
            for width in (1, 4):
                if -(1 << (8 * width - 1)) <= displacement < 1 << (8 * width - 1):
                    needle = displacement.to_bytes(width, "little", signed=True)
                    for field in occurrences(data, needle, low, high):
                        yield field, width, "disp"
            return
        if kind in ("all", "call", "branch"):
            patterns = [(rb"\xe8", 1, 4)]
            if kind != "call":
                patterns += [
                    (rb"\xe9", 1, 4),
                    (rb"[\xeb\x70-\x7f\xe0-\xe3]", 1, 1),
                    (rb"\x0f[\x80-\x8f]", 2, 4),
                ]
            for pattern, prefix, width in patterns:
                for match in re.compile(b"(?=(" + pattern + b"))").finditer(data, low, high):
                    field = match.start() + prefix
                    if field + width > high:
                        continue
                    value = int.from_bytes(data[field : field + width], "little", signed=True)
                    if (start_va + field - low + width + value) % ADDRESS_LIMIT == target:
                        yield field, width, "imm"
        if kind in ("all", "memory"):
            # All RIP/EIP ModR/M forms, including VEX and instructions with trailing immediates.
            pattern = re.compile(rb"(?=([\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}))", re.DOTALL)
            for match in pattern.finditer(data, low, high):
                field = match.start() + 1
                value = struct.unpack_from("<i", data, field)[0]
                end = start_va + field - low + 4
                if any(
                    (end + extra + value) % modulus == target
                    for extra in (0, 1, 2, 4)
                    for modulus in (ADDRESS_LIMIT, 1 << 32)
                ):
                    yield field, 4, "disp"


def references(source, *, address=None, displacement=None, kind="all", limit=100, scope=None):
    if (address is None) == (displacement is None):
        raise ValueError("Choose an address or --displacement")
    if address is not None and address.startswith("offset:"):
        raise ValueError("Reference targets use RVA or VA, not file offsets")
    target = source.va(address) if address is not None else None
    if displacement is not None:
        if displacement == 0 or not -(1 << 31) <= displacement < 1 << 31:
            raise ValueError("Displacement searches require a nonzero signed 32-bit displacement")
        if kind not in ("all", "memory"):
            raise ValueError("--displacement only supports --kind all or memory")
    scope = scope or {}
    code_spans = source.spans(**scope, executable=True) if kind != "pointer" else []
    # shortcut: broad disp8 searches are expensive; add indexing only if bounded searches stop sufficing.
    if (
        displacement is not None
        and -128 <= displacement <= 127
        and sum(b - a for a, b in code_spans) > MAX_DECODE_BYTES
    ):
        raise ValueError("disp8 searches require a --start/--length or section scope of at most 1 MiB")

    def rows():
        if kind != "pointer":
            yield from ReferenceScanner(source).code(target, kind, displacement, code_spans)
        if displacement is None and kind in ("all", "pointer"):
            needle = struct.pack("<Q", target)
            for low, high in source.spans(**scope):
                for offset in occurrences(source.data, needle, low, high):
                    yield {
                        **source.location(offset),
                        "kind": "pointer",
                        "boundary": "data_candidate",
                        "bytes_hex": needle.hex(),
                    }

    return {
        **limited(rows(), limit),
        "target": describe_va(source, target) if target is not None else None,
        "displacement": displacement,
        "code_scan_bytes": sum(b - a for a, b in code_spans),
    }


def rtti(source, name, *, slots=16, slot_start=0, limit=100):
    if not isinstance(source, PE):
        raise ValueError("RTTI inspection requires a PE file")
    if not name.startswith((".?AV", ".?AU")) or not name.endswith("@@"):
        raise ValueError("Supply an exact MSVC class/struct type name, for example .?AVActor@@")
    if not 1 <= slots <= 1024 or not 0 <= slot_start <= 65535:
        raise ValueError("Use 1..1024 slots and a starting slot of 0..65535")
    data = source.data
    seen = set()

    def tables():
        for name_offset in occurrences(data, name.encode("ascii") + b"\0"):
            try:
                name_va = source.va_of_offset(name_offset)
                td_va = name_va - 16
                source.read(td_va, 16)
                td_rva = td_va - source.base
                if not 0 < td_rva < source.image_size:
                    continue
            except ValueError:
                continue
            for reference in occurrences(data, struct.pack("<I", td_rva)):
                try:
                    if reference < 12:
                        continue
                    col_va = source.va_of_offset(reference - 12)
                    signature, offset, cd_offset, td, hierarchy, self_rva = struct.unpack(
                        "<6I", source.read(col_va, 24)
                    )
                    if signature != 1 or td != td_rva or self_rva != col_va - source.base:
                        continue
                    if not 0 < hierarchy < source.image_size:
                        continue
                    source.read(source.base + hierarchy, 16)
                except ValueError:
                    continue
                for cell in occurrences(data, struct.pack("<Q", col_va)):
                    try:
                        table_va = source.va_of_offset(cell) + 8
                        if table_va % 8 or table_va in seen:
                            continue
                        first_target = struct.unpack("<Q", source.read(table_va, 8))[0]
                        if not any(
                            r.executable and r.va <= first_target < r.va + r.size for r in source.regions
                        ):
                            continue
                    except ValueError:
                        continue
                    seen.add(table_va)
                    entries, stop = [], "slot_limit"
                    for index in range(slot_start, slot_start + slots):
                        try:
                            target = struct.unpack("<Q", source.read(table_va + index * 8, 8))[0]
                        except ValueError:
                            stop = "unavailable_slot"
                            break
                        if not any(r.executable and r.va <= target < r.va + r.size for r in source.regions):
                            stop = "target_not_in_executable_region"
                            break
                        entries.append(
                            {
                                "slot": index,
                                "cell_va": hex(table_va + index * 8),
                                "target": describe_va(source, target),
                            }
                        )
                    yield {
                        "name": name,
                        "type_descriptor_rva": hex(td_rva),
                        "col_rva": hex(self_rva),
                        "hierarchy_rva": hex(hierarchy),
                        "subobject_offset": hex(offset),
                        "constructor_displacement": hex(cd_offset),
                        "vtable_rva": hex(table_va - source.base),
                        "vtable_va": hex(table_va),
                        "slots": entries,
                        "stop_reason": stop,
                    }

    return limited(tables(), limit)
