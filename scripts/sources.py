from __future__ import annotations

import bisect
import hashlib
import struct
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

lazy import pefile

ADDRESS_LIMIT = 1 << 64


def integer(value, *, signed=False):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"Expected an integer, got {value!r}")
    number = int(value, 0) if isinstance(value, str) else value
    if not -(ADDRESS_LIMIT // 2 if signed else 0) <= number < ADDRESS_LIMIT:
        raise ValueError("Integer is outside the supported 64-bit range")
    return number


def coordinate(text):
    try:
        mode, value = text.split(":", 1)
    except ValueError as exc:
        raise ValueError("Use an explicit address: rva:0x1000, va:0x140001000, or offset:0x400") from exc
    if mode not in ("rva", "va", "offset"):
        raise ValueError(f"Unknown address mode: {mode}")
    return mode, integer(value)


@dataclass(frozen=True)
class Region:
    name: str
    offset: int
    size: int
    va: int
    executable: bool | None = None


class ByteSource:
    def __init__(self, path, data, kind, regions, *, base=None, image_size=None):
        self.path = Path(path).resolve()
        self.data = data
        self.regions = regions
        self.base = base
        self.image_size = image_size
        self.metadata = {
            "kind": kind,
            "path": str(self.path),
            "byte_count": len(data),
            "bytes_sha256": hashlib.sha256(data).hexdigest(),
        }
        if base is not None:
            self.metadata.update(image_base=hex(base), image_size=image_size)

    @cached_property
    def imports(self):
        return {}

    def owner(self, va):
        return None

    def va_of_offset(self, offset):
        if not 0 <= offset < len(self.data):
            raise ValueError("Offset is outside the available bytes")
        for region in self.regions:
            if region.offset <= offset < region.offset + region.size:
                return region.va + offset - region.offset
        raise ValueError("File offset has no mapped VA")

    def region_at(self, va):
        for region in self.regions:
            if region.va <= va < region.va + region.size:
                return region
        raise ValueError(f"No bytes available at {va:#x}")

    def location(self, offset):
        if not 0 <= offset < len(self.data):
            raise ValueError("Offset is outside the available bytes")
        row = {"offset": hex(offset), "va": None, "rva": None, "region": None}
        for region in self.regions:
            if region.offset <= offset < region.offset + region.size:
                va = region.va + offset - region.offset
                row.update(va=hex(va), region=region.name)
                if self.base is not None and self.base <= va < self.base + self.image_size:
                    row["rva"] = hex(va - self.base)
                break
        return row

    def offset_of_va(self, va, count=1):
        if count <= 0 or not 0 <= va < va + count <= ADDRESS_LIMIT:
            raise ValueError("Invalid address range")
        region = self.region_at(va)
        available = region.va + region.size - va
        if count > available:
            raise ValueError(
                f"Read at {va:#x} needs {count} bytes; only {available} available in {region.name}"
            )
        return region.offset + va - region.va

    def va(self, address):
        mode, value = coordinate(address)
        if mode == "va":
            return value
        if mode == "rva":
            if self.base is None:
                raise ValueError("This source has no known image base; use VA or offset")
            if value >= self.image_size:
                raise ValueError("RVA is outside the source image")
            return self.base + value
        return self.va_of_offset(value)

    def offset(self, address, count=1):
        mode, value = coordinate(address)
        if mode == "offset":
            if count <= 0 or value + count > len(self.data):
                raise ValueError("Read exceeds available bytes")
            return value
        return self.offset_of_va(self.va(address), count)

    def read(self, va, count):
        offset = self.offset_of_va(va, count)
        return self.data[offset : offset + count]

    def spans(self, *, section=None, start=None, length=None, executable=False):
        if (start is None) != (length is None):
            raise ValueError("Supply --start and --length together")
        low, high = 0, len(self.data)
        if start is not None:
            low = self.offset(start, length)
            high = low + length
        if section or executable:
            regions = [r for r in self.regions if (not section or r.name == section)]
            if not regions:
                raise ValueError(f"Section not found: {section}")
            if executable:
                regions = [r for r in regions if r.executable is not False]
            ranges = [(r.offset, r.offset + r.size) for r in regions]
        else:
            ranges = [(0, len(self.data))]
        return [(max(a, low), min(b, high)) for a, b in ranges if max(a, low) < min(b, high)]


class PE(ByteSource):
    def __init__(self, path):
        data = Path(path).read_bytes()
        self.pe = pefile.PE(data=data, fast_load=True)
        pe = self.pe
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise ValueError("Only AMD64 PE32+ images are supported")
        base = pe.OPTIONAL_HEADER.ImageBase
        size = pe.OPTIONAL_HEADER.SizeOfImage
        headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        if not 0 < headers <= len(data) or not headers <= size or base + size > ADDRESS_LIMIT:
            raise ValueError("Invalid PE header/image bounds")
        if len(pe.sections) != pe.FILE_HEADER.NumberOfSections:
            raise ValueError("Truncated PE section table")
        regions = [Region("headers", 0, headers, base, executable=False)]
        for section in pe.sections:
            offset = section.get_PointerToRawData_adj()
            rva = section.get_VirtualAddress_adj()
            raw_size = section.SizeOfRawData
            if not raw_size:
                continue
            if offset + raw_size > len(data) or rva + raw_size > size:
                raise ValueError("Truncated or out-of-image PE section")
            regions.append(
                Region(
                    section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                    offset,
                    raw_size,
                    base + rva,
                    bool(section.Characteristics & 0x20000000),
                )
            )
        for key in ("offset", "va"):
            ordered = sorted(regions, key=lambda r: getattr(r, key))
            if any(getattr(a, key) + a.size > getattr(b, key) for a, b in zip(ordered, ordered[1:])):
                raise ValueError("Overlapping PE regions are unsupported")
        super().__init__(path, data, "pe_file", regions, base=base, image_size=size)
        self.metadata.update(
            machine="AMD64",
            entry_rva=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            pe_timestamp=hex(pe.FILE_HEADER.TimeDateStamp),
        )

    @property
    def sections(self):
        return [
            {
                "name": s.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                "rva": hex(s.get_VirtualAddress_adj()),
                "virtual_size": s.Misc_VirtualSize,
                "offset": hex(s.get_PointerToRawData_adj()),
                "raw_size": s.SizeOfRawData,
                "characteristics": hex(s.Characteristics),
            }
            for s in self.pe.sections
        ]

    def directory(self, index):
        directories = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if index >= len(directories):
            return 0, 0
        entry = directories[index]
        if bool(entry.VirtualAddress) != bool(entry.Size):
            raise ValueError(f"Incomplete PE data directory {index}")
        return entry.VirtualAddress, entry.Size

    @cached_property
    def imports(self):
        self.pe.parse_data_directories(directories=[1, 13])
        result = {}
        for attribute, delayed in (("DIRECTORY_ENTRY_IMPORT", False), ("DIRECTORY_ENTRY_DELAY_IMPORT", True)):
            for library in getattr(self.pe, attribute, []):
                for symbol in library.imports:
                    result[symbol.address] = {
                        "dll": library.dll.decode("ascii", errors="replace"),
                        "name": symbol.name.decode("ascii", errors="replace") if symbol.name else None,
                        "ordinal": symbol.ordinal,
                        "iat_va": hex(symbol.address),
                        "iat_rva": hex(symbol.address - self.base),
                        "delayed": delayed,
                    }
        return result

    @cached_property
    def exports(self):
        self.pe.parse_data_directories(directories=[0])
        directory = getattr(self.pe, "DIRECTORY_ENTRY_EXPORT", None)
        return [
            {
                "name": symbol.name.decode("ascii", errors="replace") if symbol.name else None,
                "ordinal": symbol.ordinal,
                "rva": hex(symbol.address),
                "forwarder": symbol.forwarder.decode("ascii", errors="replace") if symbol.forwarder else None,
            }
            for symbol in (directory.symbols if directory else [])
        ]

    @cached_property
    def entries(self):
        rva, size = self.directory(3)
        if not size:
            return []
        if size % 12:
            raise ValueError("Exception directory size is not a multiple of RUNTIME_FUNCTION size")
        entries = [
            entry
            for entry in struct.iter_unpack("<III", self.read(self.base + rva, size))
            if entry[0] != entry[1]
        ]
        previous = 0
        for begin, end, unwind in entries:
            if not previous <= begin < end <= self.image_size or not 0 < unwind < self.image_size:
                raise ValueError("Invalid, overlapping, or unsorted exception-directory entries")
            previous = end
        return entries

    @cached_property
    def starts(self):
        return [entry[0] for entry in self.entries]

    def owner(self, va):
        rva = va - self.base
        index = bisect.bisect_right(self.starts, rva) - 1
        return self.entries[index] if index >= 0 and rva < self.entries[index][1] else None

    def unwind_chain(self, entry):
        chain, seen = [], set()
        while True:
            if entry in seen or len(chain) >= 64:
                raise ValueError("Cyclic or excessive unwind chain")
            seen.add(entry)
            begin, end, unwind = entry
            if not 0 <= begin < end <= self.image_size or unwind & 3:
                raise ValueError("Invalid chained RUNTIME_FUNCTION")
            chain.append(entry)
            header = self.read(self.base + unwind, 4)
            version, flags = header[0] & 7, header[0] >> 3
            if version not in (1, 2):
                raise ValueError(f"Unsupported unwind-info version: {version}")
            if not flags & 4:
                return chain
            if flags & 3:
                raise ValueError("Chained unwind info also specifies a handler")
            offset = (4 + header[2] * 2 + 3) & ~3
            entry = struct.unpack("<III", self.read(self.base + unwind + offset, 12))

    def unwind_region(self, va):
        entry = self.owner(va)
        if entry is None:
            raise ValueError("No unwind range contains this address; supply an explicit --bytes range")
        chain = self.unwind_chain(entry)
        root = chain[-1]
        index = bisect.bisect_left(self.starts, entry[0])
        first = last = index
        while first and self.entries[first - 1][1] == self.entries[first][0]:
            if self.unwind_chain(self.entries[first - 1])[-1] != root:
                break
            first -= 1
        while last + 1 < len(self.entries) and self.entries[last][1] == self.entries[last + 1][0]:
            if self.unwind_chain(self.entries[last + 1])[-1] != root:
                break
            last += 1
        return {
            "begin_rva": self.entries[first][0],
            "end_rva": self.entries[last][1],
            "chain": [{"begin_rva": a, "end_rva": b, "unwind_rva": c} for a, b, c in chain],
            "contiguous_entries": last - first + 1,
        }


def raw_source(path, start_va, *, module_base=None, module_size=None):
    if (module_base is None) != (module_size is None):
        raise ValueError("--module-base and --module-size must be supplied together")
    if module_base is not None:
        module_base, module_size = integer(module_base), integer(module_size)
        if not module_size or module_base + module_size > ADDRESS_LIMIT:
            raise ValueError("Invalid raw module bounds")
    start_va = integer(start_va)
    data = Path(path).read_bytes()
    if not data or start_va + len(data) > ADDRESS_LIMIT:
        raise ValueError("Empty or out-of-address-space raw byte range")
    source = ByteSource(
        path,
        data,
        "raw",
        [Region("raw", 0, len(data), start_va)],
        base=module_base,
        image_size=module_size,
    )
    source.metadata["start_va"] = hex(start_va)
    return source
