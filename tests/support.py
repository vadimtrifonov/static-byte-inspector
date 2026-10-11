import struct
from pathlib import Path

BASE = 0x140000000


def fixture(path):
    data = bytearray(0x1200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 3, 0x65A00001, 0, 0, 240, 0x2022)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<IIQII", data, opt + 16, 0x1000, 0x1000, BASE, 0x1000, 0x200)
    struct.pack_into("<II", data, opt + 56, 0x4000, 0x400)
    struct.pack_into("<H", data, opt + 68, 3)
    struct.pack_into("<I", data, opt + 108, 16)
    for index, (name, rva, offset, size, virtual, flags) in enumerate(
        [
            (b".text", 0x1000, 0x400, 0x400, 0x500, 0x60000020),
            (b".rdata", 0x2000, 0x800, 0x800, 0x800, 0x40000040),
            (b".pdata", 0x3000, 0x1000, 0x200, 0x200, 0x40000040),
        ]
    ):
        section = opt + 240 + index * 40
        data[section : section + 8] = name.ljust(8, b"\0")
        struct.pack_into("<IIII", data, section + 8, virtual, rva, size, offset)
        struct.pack_into("<I", data, section + 36, flags)
    data[0x400:0x800] = b"\xcc" * 0x400

    def put(rva, raw):
        offset = rva - (0xC00 if rva < 0x2000 else 0x1800 if rva < 0x3000 else 0x2000)
        data[offset : offset + len(raw)] = raw

    def rel(origin, prefix, target, suffix=b""):
        return prefix + struct.pack("<i", target - origin - len(prefix) - 4 - len(suffix)) + suffix

    put(0x1000, rel(0x1000, b"\x48\x8d\x0d", 0x2040))
    put(0x1007, rel(0x1007, b"\xe8", 0x1050))
    put(0x100C, b"\x48\xb8" + rel(0x100E, b"\xe8", 0x1050) + b"\xaa\xbb\xcc")
    put(0x1016, rel(0x1016, b"\x83\x3d", 0x2040, b"\x01"))
    put(0x101D, b"\x90\x90\xc3")
    put(0x1020, b"\x8b\x81\xf4\x03\0\0")
    put(0x1026, rel(0x1026, b"\xc5\xfa\x10\x05", 0x2040))
    put(0x102E, b"\xeb\x00")
    put(0x1030, b"\x90\xc3")
    put(0x1040, rel(0x1040, b"\xe8", 0x1050))
    put(0x1050, rel(0x1050, b"\xff\x15", 0x2190) + b"\xc3")
    put(0x1060, rel(0x1060, b"\x2e\xe8", 0x1050) + b"\xc3")
    put(0x2040, b"AnchorName\0")
    put(0x2060, "WideName\0".encode("utf-16le"))
    put(0x2080, struct.pack("<QQ", BASE + 0x1050, BASE + 0x2040))
    # One ordinary import.
    struct.pack_into("<II", data, opt + 112 + 8, 0x2100, 40)
    put(0x2100, struct.pack("<5I", 0x2180, 0, 0, 0x2150, 0x2190))
    put(0x2150, b"KERNEL32.dll\0")
    put(0x2170, b"\0\0LoadLibraryW\0")
    put(0x2180, struct.pack("<Q", 0x2170))
    put(0x2190, struct.pack("<Q", 0x2170))
    # An odd unwind-code count exercises DWORD alignment of the embedded parent.
    put(0x2200, b"\x01\0\0\0")
    put(0x2210, b"\x21\0\x01\0\0\0\0\0" + struct.pack("<III", 0x1000, 0x1020, 0x2200))
    for rva in (0x2230, 0x2240, 0x2250):
        put(rva, b"\x01\0\0\0")
    entries = [
        (0x1000, 0x1020, 0x2200),
        (0x1020, 0x1030, 0x2210),
        (0x1030, 0x1040, 0x2230),
        (0x1050, 0x1060, 0x2240),
        (0x1060, 0x1070, 0x2250),
    ]
    put(0x3000, b"".join(struct.pack("<III", *entry) for entry in entries))
    struct.pack_into("<II", data, opt + 112 + 3 * 8, 0x3000, len(entries) * 12)
    # A named export and an ordinal-only forwarder.
    struct.pack_into("<II", data, opt + 112, 0x2280, 0x100)
    put(0x2280, struct.pack("<IIHH7I", 0, 0, 0, 0, 0x22B0, 1, 2, 1, 0x22C0, 0x22D0, 0x22D8))
    put(0x22B0, b"fixture.dll\0")
    put(0x22C0, struct.pack("<II", 0x1050, 0x22F0))
    put(0x22D0, struct.pack("<I", 0x22E0))
    put(0x22D8, b"\0\0")
    put(0x22E0, b"Exported\0")
    put(0x22F0, b"OTHER.forwarded\0")
    # The secondary COL deliberately precedes the primary COL.
    put(0x2410, b".?AVWidget@@\0")
    put(0x2440, struct.pack("<6I", 1, 0x48, 0, 0x2400, 0x2480, 0x2440))
    put(0x2460, struct.pack("<6I", 1, 0, 0, 0x2400, 0x2480, 0x2460))
    put(0x2480, struct.pack("<4I", 0, 0, 1, 0x2490))
    put(0x2500, struct.pack("<QQQ", BASE + 0x2440, BASE + 0x1050, 0))
    put(0x2540, struct.pack("<QQQQ", BASE + 0x2460, BASE + 0x1050, BASE + 0x1000, 0))
    data.extend(b"OverlayAnchor\0")
    Path(path).write_bytes(data)
    return Path(path)
