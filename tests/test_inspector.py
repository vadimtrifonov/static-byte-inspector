import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import BASE, fixture

from scripts.__main__ import parser, run
from scripts.analysis import disassemble, read_data, references, rtti, search
from scripts.sources import ADDRESS_LIMIT, PE, raw_source

ROOT = Path(__file__).resolve().parents[1]


class InspectorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="static-byte-inspector-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = fixture(self.root / "fixture.dll")
        self.source = PE(self.path)

    def test_identity_mapping_imports_and_exports(self):
        source = self.source
        self.assertEqual(source.metadata["bytes_sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(source.location(0x840)["rva"], "0x2040")
        self.assertEqual(source.va("rva:0x2040"), BASE + 0x2040)
        self.assertEqual(source.va_of_offset(0x840), BASE + 0x2040)
        self.assertEqual(source.offset("va:0x140002040"), 0x840)
        self.assertEqual(source.imports[BASE + 0x2190]["name"], "LoadLibraryW")
        self.assertEqual(source.exports[0]["name"], "Exported")
        self.assertEqual(source.exports[1]["forwarder"], "OTHER.forwarded")
        self.assertIsNone(source.exports[1]["name"])
        for address, count in ((BASE + 0x1400, 1), (BASE + 0x13FF, 2), (BASE + 0x3FFF, 2)):
            with self.subTest(address=address), self.assertRaises(ValueError):
                source.read(address, count)

    def test_strings_overlay_wildcards_and_exact_counts(self):
        overlay = search(self.source, text="OverlayAnchor")
        self.assertEqual(overlay["total"], 1)
        self.assertIsNone(overlay["results"][0]["rva"])
        wide = search(self.source, text="WideName", encoding="both")
        self.assertEqual(wide["results"][0]["rva"], "0x2060")
        self.assertEqual(search(self.source, pattern="48 8D ?? ?? ?? ?? ??")["total"], 1)
        zeros = search(self.source, pattern="00 00", limit=2)
        self.assertTrue(zeros["truncated"])
        self.assertGreater(zeros["total"], len(zeros["results"]))
        limited = search(self.source, text="AnchorName", scope={"section": ".text"})
        self.assertEqual(limited["total"], 0)
        pointer = search(self.source, value=str(BASE + 0x2040), value_type="u64")
        self.assertEqual(pointer["results"][0]["rva"], "0x2088")
        raw_path = self.root / "overlap.bin"
        raw_path.write_bytes(b"AAA")
        overlap = search(raw_source(raw_path, 0x1000), text="AA")
        self.assertEqual(overlap["total"], 2)
        for kwargs in ({"pattern": "?? ??"}, {"pattern": "GG"}, {"text": ""}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                search(self.source, **kwargs)

    def test_callers_validate_boundaries_and_preserve_candidates(self):
        result = references(self.source, address="rva:0x1050", kind="call")
        rows = {row["rva"]: row for row in result["results"]}
        self.assertEqual(set(rows), {"0x1007", "0x1040", "0x1060"})
        self.assertEqual(rows["0x1007"]["boundary"], "unwind_linear")
        self.assertEqual(rows["0x1040"]["boundary"], "candidate_no_unwind")
        self.assertEqual(rows["0x1060"]["bytes_hex"][:2], "2e")
        self.assertNotIn("0x100e", rows)  # An E8 inside movabs is not a call instruction.
        pointer = references(self.source, address="rva:0x1050", kind="pointer")
        self.assertIn("0x2080", [row["rva"] for row in pointer["results"]])
        branch = references(self.source, address="rva:0x1030", kind="branch")
        self.assertEqual(branch["results"][0]["rva"], "0x102e")

    def test_memory_refs_cover_vex_trailing_immediates_and_import_slots(self):
        result = references(self.source, address="rva:0x2040", kind="memory")
        self.assertEqual({row["rva"] for row in result["results"]}, {"0x1000", "0x1016", "0x1026"})
        imported = references(self.source, address="rva:0x2190", kind="memory")
        row = imported["results"][0]
        self.assertEqual(row["rva"], "0x1050")
        self.assertEqual(imported["target"]["import"]["name"], "LoadLibraryW")
        self.assertEqual(row["indirect_control_flow"], "memory_cell")
        field = references(self.source, displacement=0x3F4)
        self.assertEqual([row["rva"] for row in field["results"]], ["0x1020"])
        with self.assertRaisesRegex(ValueError, "nonzero"):
            references(self.source, displacement=0)

    def test_reference_scans_deduplicate_operand_fields(self):
        path = self.root / "refs.bin"
        path.write_bytes(
            bytes.fromhex("488d05f90f0000" + "c5f8118424e0010000" * 2 + "488d4c2440e8dd00000048ff15d6100000")
        )
        source = raw_source(path, 0x1000)
        memory = references(source, address="va:0x2000", kind="memory")
        self.assertEqual(memory["total"], 1)
        self.assertEqual(memory["results"][0]["bytes_hex"], "488d05f90f0000")
        fields = references(source, displacement=0x1E0)
        self.assertEqual(fields["total"], 2)
        self.assertEqual([row["va"] for row in fields["results"]], ["0x1007", "0x1010"])
        self.assertTrue(all(row["mnemonic"] == "vmovups" for row in fields["results"]))
        self.assertTrue(all(row["boundary"] == "candidate_no_unwind" for row in fields["results"]))
        calls = references(source, address="va:0x1100", kind="call")
        self.assertEqual([row["va"] for row in calls["results"]], ["0x101e"])
        indirect = references(source, address="va:0x2100", kind="memory")
        self.assertEqual([row["bytes_hex"] for row in indirect["results"]], ["48ff15d6100000"])

        raw = bytearray(self.path.read_bytes())
        raw[0x44F] = 0x48  # A prefix before a function must not hide its verified first instruction.
        self.path.write_bytes(raw)
        imported = references(PE(self.path), address="rva:0x2190", kind="memory")
        self.assertEqual(imported["total"], 1)
        self.assertEqual(imported["results"][0]["rva"], "0x1050")
        self.assertEqual(imported["results"][0]["boundary"], "unwind_linear")

    def test_loop_references_preserve_counter_address_size(self):
        path = self.root / "loop.bin"
        for code in ("67e006", "67e106", "67e206"):
            with self.subTest(code=code):
                path.write_bytes(bytes.fromhex(code))
                result = references(raw_source(path, 0x1000), address="va:0x1009", kind="branch")
                self.assertEqual([row["bytes_hex"] for row in result["results"]], [code])
                self.assertEqual(result["results"][0]["boundary"], "candidate_no_unwind")

    def test_eip_relative_addresses_and_negative_displacements(self):
        raw = bytearray(self.path.read_bytes())
        origin = BASE + 0x1070
        displacement = 0x2040 - ((origin + 8) % (1 << 32))
        code = b"\x67\x48\x8b\x05" + struct.pack("<i", displacement) + b"\x48\x8b\x41\xf8\xc3"
        raw[0x470 : 0x470 + len(code)] = code
        path = self.root / "addressing.dll"
        path.write_bytes(raw)
        source = PE(path)
        result = references(source, address="va:0x2040", kind="memory")
        self.assertEqual([row["rva"] for row in result["results"]], ["0x1070"])
        result = references(source, displacement=-8, scope={"start": "rva:0x1070", "length": len(code)})
        self.assertIn("0x1078", [row["rva"] for row in result["results"]])

    def test_chained_unwind_merges_only_adjacent_fragments_with_same_root(self):
        region = self.source.unwind_region(BASE + 0x1028)
        self.assertEqual((region["begin_rva"], region["end_rva"]), (0x1000, 0x1030))
        self.assertEqual(len(region["chain"]), 2)
        listing = disassemble(self.source, "rva:0x1028", unwind=True)
        self.assertEqual(listing["origin_va"], hex(BASE + 0x1000))
        self.assertEqual(listing["unwind_region"]["begin_rva"], "0x1000")
        self.assertEqual(listing["decoded_bytes"], 0x30)
        self.assertEqual(listing["stop_reason"], "range_end")
        self.assertIn("0x1026", [row["rva"] for row in listing["instructions"]])
        with self.assertRaisesRegex(ValueError, "No unwind"):
            disassemble(self.source, "rva:0x1040", unwind=True)
        raw = bytearray(self.path.read_bytes())
        struct.pack_into("<III", raw, 0xA18, 0x1020, 0x1030, 0x2210)
        bad = self.root / "cycle.dll"
        bad.write_bytes(raw)
        cyclic = PE(bad)
        with self.assertRaisesRegex(ValueError, "Cyclic"):
            cyclic.unwind_region(BASE + 0x1020)

    def test_empty_unwind_entries_leave_valid_ranges_intact(self):
        expected = self.source.entries
        entries = [expected[0], (0x1020, 0x1020, 0x2210), *expected[1:]]
        raw = bytearray(self.path.read_bytes())
        table = b"".join(struct.pack("<III", *entry) for entry in entries)
        raw[0x1000 : 0x1000 + len(table)] = table
        struct.pack_into("<I", raw, 0x98 + 112 + 3 * 8 + 4, len(table))
        self.path.write_bytes(raw)
        source = PE(self.path)
        self.assertEqual(source.entries, expected)
        self.assertEqual(source.owner(BASE + 0x1020), expected[1])
        self.assertEqual(disassemble(source, "rva:0x1020", unwind=True)["decoded_bytes"], 0x30)
        report = run(parser().parse_args(["info", "--file", str(self.path)]))
        self.assertEqual(report["unwind_entry_count"], len(expected))
        struct.pack_into("<III", raw, 0x100C, 0x1021, 0x1020, 0x2210)
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "exception-directory"):
            _ = PE(self.path).entries

    def test_disassembly_bounds_output_and_decode_gaps(self):
        result = disassemble(self.source, "rva:0x1000", byte_count=32, limit=1)
        self.assertEqual(result["stop_reason"], "output_limit")
        self.assertEqual(result["decoded_bytes"], 7)
        self.assertEqual(result["remaining_bytes"], 25)
        self.assertEqual(result["instructions"][0]["references"][0]["string"]["text"], "AnchorName")
        raw_path = self.root / "truncated.bin"
        raw_path.write_bytes(b"\x90\x0f")
        result = disassemble(raw_source(raw_path, 0x1000), "offset:0")
        self.assertEqual(result["byte_count"], 2)
        self.assertEqual(result["stop_reason"], "invalid_or_truncated_instruction")
        self.assertEqual(result["decoded_bytes"], 1)
        self.assertNotIn("references", result["instructions"][0])
        self.assertEqual(disassemble(self.source, "rva:0x13fe")["byte_count"], 2)
        self.assertEqual(disassemble(self.source, "rva:0x1000")["byte_count"], 256)
        with self.assertRaisesRegex(ValueError, "only 2 available"):
            disassemble(self.source, "rva:0x13fe", byte_count=3)
        with self.assertRaises(ValueError):
            disassemble(self.source, "offset:0x1200", byte_count=2)

    def test_raw_origin_is_reported_and_unknown_permissions_allow_code_scans(self):
        path = self.root / "raw.bin"
        path.write_bytes(bytes.fromhex("e8fb000000ffd0c3"))
        reports = [
            run(parser().parse_args(["info", "--raw", str(path), "--start-va", base]))
            for base in ("0x1000", "0x9000")
        ]
        self.assertEqual([r["source"]["start_va"] for r in reports], ["0x1000", "0x9000"])
        self.assertEqual(reports[0]["source"]["bytes_sha256"], reports[1]["source"]["bytes_sha256"])
        source = raw_source(path, 0x1000)
        listing = disassemble(source, "offset:0")
        self.assertEqual(listing["byte_count"], 8)
        self.assertEqual(listing["instructions"][1]["indirect_control_flow"], "unresolved")
        self.assertNotIn("references", listing["instructions"][1])
        calls = references(source, address="va:0x1100", kind="call")
        self.assertEqual(calls["total"], 1)
        self.assertEqual(calls["results"][0]["boundary"], "candidate_no_unwind")
        with self.assertRaisesRegex(ValueError, "image base"):
            source.va("rva:0")

    def test_typed_reads_nonfinite_floats_and_pointer_annotations(self):
        result = read_data(self.source, "rva:0x2080", "pointer", 2)
        self.assertEqual(result["results"][1]["target"]["string"]["text"], "AnchorName")
        self.assertEqual(read_data(self.source, "offset:0x1200", "u8", 1)["results"][0]["value"], ord("O"))
        raw_path = self.root / "nan.bin"
        raw_path.write_bytes(struct.pack("<f", float("nan")))
        result = read_data(raw_source(raw_path, 0), "offset:0", "f32", 1)
        self.assertEqual(result["results"][0]["value"], "nan")
        json.dumps(result, allow_nan=False)
        with self.assertRaises(ValueError):
            read_data(self.source, "rva:0x13ff", "u32", 1)

    def test_rtti_keeps_secondary_and_primary_tables_distinct(self):
        result = rtti(self.source, ".?AVWidget@@", slots=8)
        self.assertEqual(result["total"], 2)
        self.assertEqual([row["subobject_offset"] for row in result["results"]], ["0x48", "0x0"])
        primary = result["results"][1]
        self.assertEqual(primary["vtable_rva"], "0x2548")
        self.assertEqual([slot["target"]["rva"] for slot in primary["slots"]], ["0x1050", "0x1000"])
        self.assertEqual(primary["stop_reason"], "target_not_in_executable_region")
        selected = rtti(self.source, ".?AVWidget@@", slot_start=1, slots=1)
        self.assertEqual(selected["results"][1]["stop_reason"], "slot_limit")
        self.assertEqual(selected["results"][1]["slots"][0]["slot"], 1)

    def test_raw_module_coordinates_preserve_context_and_reference_boundaries(self):
        path = self.root / "window.bin"
        raw = b"\x90" * 27 + bytes.fromhex("488d4c2440e8fb000000c3") + b"\x90" * 59
        path.write_bytes(raw)
        base = 0x7FF600000000
        source = raw_source(path, base + 0xFE0, module_base=base, module_size=0x4000)
        self.assertEqual(source.va("offset:0"), base + 0xFE0)
        self.assertEqual(source.location(0)["rva"], "0xfe0")
        self.assertEqual(source.metadata["bytes_sha256"], hashlib.sha256(raw).hexdigest())
        calls = references(source, address="rva:0x1100", kind="call")
        self.assertEqual([row["rva"] for row in calls["results"]], ["0x1000"])
        result = run(
            parser().parse_args(
                [
                    "disasm",
                    "rva:0x1000",
                    "--raw",
                    str(path),
                    "--start-va",
                    hex(base + 0xFE0),
                    "--module-base",
                    hex(base),
                    "--module-size",
                    "0x4000",
                ]
            )
        )
        self.assertEqual(result["source"]["image_base"], hex(base))
        self.assertEqual(result["source"]["image_size"], 0x4000)
        self.assertEqual(result["origin_va"], hex(base + 0x1000))
        self.assertEqual(result["byte_count"], 65)
        self.assertEqual(result["instructions"][0]["bytes_hex"], "e8fb000000")
        reference = result["instructions"][0]["references"][0]
        self.assertEqual(
            (reference["va"], reference["rva"], reference["available"]), (hex(base + 0x1100), "0x1100", False)
        )
        with self.assertRaisesRegex(ValueError, "only 65 available"):
            disassemble(source, "rva:0x1000", byte_count=256)
        with self.assertRaisesRegex(ValueError, "No bytes"):
            disassemble(source, "rva:0x2000")
        with self.assertRaisesRegex(ValueError, "outside the source image"):
            source.va("rva:0x4000")
        with self.assertRaisesRegex(ValueError, "requires a PE"):
            disassemble(source, "rva:0x1000", unwind=True)

        # Module coordinates do not imply that all raw bytes belong to that module.
        source = raw_source(path, base + 0x5000, module_base=base, module_size=0x4000)
        self.assertIsNone(source.location(0)["rva"])
        listing = disassemble(source, "offset:32")
        self.assertNotIn("rva", listing["instructions"][0]["references"][0])

    def test_raw_inputs_reject_incomplete_or_overflowing_address_metadata(self):
        path = self.root / "raw.bin"
        path.write_bytes(b"\x90\xc3")
        for options in (
            {"module_base": 0},
            {"module_size": 0x1000},
            {"module_base": 0, "module_size": 0},
            {"module_base": -1, "module_size": 0x1000},
            {"module_base": ADDRESS_LIMIT - 1, "module_size": 2},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                raw_source(path, 0x1000, **options)
        with self.assertRaises(ValueError):
            raw_source(path, ADDRESS_LIMIT - 1)
        edge = raw_source(path, ADDRESS_LIMIT - 2, module_base=ADDRESS_LIMIT - 2, module_size=2)
        self.assertEqual(edge.va("rva:0x1"), ADDRESS_LIMIT - 1)
        with self.assertRaisesRegex(ValueError, "require --raw"):
            run(parser().parse_args(["info", "--file", str(self.path), "--module-base", "0"]))
        for arguments in (["--raw", str(path)], ["--file", str(self.path), "--start-va", "0"]):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(ValueError, "together"):
                run(parser().parse_args(["info", *arguments]))
        path.write_bytes(b"")
        with self.assertRaises(ValueError):
            raw_source(path, 0)

    def test_invalid_pe_architecture_and_layout_are_rejected(self):
        for mutate in (
            lambda raw: struct.pack_into("<H", raw, 0x84, 0x14C),
            lambda raw: struct.pack_into("<I", raw, 0x188 + 40 + 20, 0x400),
        ):
            raw = bytearray(self.path.read_bytes())
            mutate(raw)
            path = self.root / "invalid.dll"
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                PE(path)

    def test_all_cli_commands_are_read_only_and_emit_json(self):
        before = self.path.read_bytes()
        commands = [
            ["info"],
            ["find", "--text", "AnchorName"],
            ["refs", "rva:0x2040", "--kind", "memory"],
            ["disasm", "rva:0x1020", "--unwind"],
            ["data", "rva:0x2080", "--type", "pointer", "--count", "2"],
            ["rtti", ".?AVWidget@@", "--slots", "1"],
        ]
        for command in commands:
            completed = subprocess.run(
                [sys.executable, "-B", "-m", "scripts", *command, "--file", str(self.path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            with self.subTest(command=command):
                self.assertEqual(completed.returncode, 0, completed.stderr)
                report = json.loads(completed.stdout)
                self.assertEqual(report["command"], command[0])
                if command[0] == "info":
                    self.assertEqual([s["name"] for s in report["sections"]], [".text", ".rdata", ".pdata"])
        self.assertEqual(self.path.read_bytes(), before)
        failed = subprocess.run(
            [sys.executable, "-B", "-m", "scripts", "disasm", "rva:0x1400", "--file", str(self.path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(failed.stdout, "")
        self.assertNotIn("Traceback", failed.stderr)
        with self.assertRaisesRegex(ValueError, "together"):
            run(
                parser().parse_args(
                    ["find", "--file", str(self.path), "--text", "Anchor", "--start", "rva:0x1000"]
                )
            )


if __name__ == "__main__":
    unittest.main()
