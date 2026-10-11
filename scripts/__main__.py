import argparse
import json
import struct
import sys
from pathlib import Path
lazy from importlib.metadata import version

lazy import capstone
lazy import pefile

from .analysis import FORMATS, disassemble, limited, read_data, references, rtti, search
from .sources import PE, integer, raw_source


def number(text):
    try:
        return integer(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def signed_number(text):
    try:
        return integer(text, signed=True)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def parser():
    root = argparse.ArgumentParser(
        description="Read-only offline AMD64 PE and raw-byte inspection; JSON on stdout."
    )
    commands = root.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("info", "Source identity and available PE metadata/imports/exports"),
        ("find", "Search text, wildcard byte signatures, or encoded numbers"),
        ("refs", "Find candidate references to an address or field displacement"),
        ("disasm", "Disassemble an explicit byte range or contiguous unwind region"),
        ("data", "Read a typed array or pointer table"),
        ("rtti", "Find MSVC x64 vtables by decorated type name"),
    ):
        command = commands.add_parser(name, help=help_text)
        sources = command.add_mutually_exclusive_group(required=True)
        sources.add_argument("--file", type=Path, help="AMD64 PE32+ file")
        sources.add_argument("--raw", type=Path, help="Raw AMD64 byte file")
        command.add_argument("--start-va", type=number, help="VA of the first byte of --raw")
        command.add_argument(
            "--module-base", type=number, help="Module VA for raw RVA addressing; requires --module-size"
        )
        command.add_argument(
            "--module-size", type=number, help="Module image size for --raw; requires --module-base"
        )
        if name != "data":
            command.add_argument(
                "--limit", type=number, default=100, help="Maximum displayed results (1..10000; default 100)"
            )
        if name in ("find", "refs"):
            command.add_argument("--section", help="Exact source region/PE section name")
            command.add_argument("--start", help="Scan start: rva:N, va:N, or offset:N; requires --length")
            command.add_argument("--length", type=number, help="Scan byte count; requires --start")
        if name == "find":
            queries = command.add_mutually_exclusive_group(required=True)
            queries.add_argument("--text")
            queries.add_argument("--pattern", help="Space-separated bytes with ?? wildcards")
            queries.add_argument("--value", help="Numeric value encoded according to --type")
            command.add_argument("--encoding", choices=("ascii", "utf-16le", "both"), default="ascii")
            command.add_argument("--type", choices=FORMATS, default="u32")
        elif name == "refs":
            command.add_argument("address", nargs="?", help="Target: rva:N or va:N")
            command.add_argument(
                "--displacement", type=signed_number, help="Nonzero signed memory displacement"
            )
            command.add_argument(
                "--kind", choices=("all", "call", "branch", "memory", "pointer"), default="all"
            )
        elif name in ("disasm", "data"):
            command.add_argument("address", help="rva:N, va:N, or offset:N")
            if name == "disasm":
                bounds = command.add_mutually_exclusive_group()
                bounds.add_argument(
                    "--bytes",
                    type=number,
                    help="Exact byte count; default up to 256 available bytes (maximum 1 MiB)",
                )
                bounds.add_argument(
                    "--unwind",
                    action="store_true",
                    help="Use PE unwind metadata around the requested address",
                )
            else:
                command.add_argument("--type", choices=FORMATS, default="u8")
                command.add_argument("--count", type=number, default=16)
        elif name == "rtti":
            command.add_argument("name", help="Exact decorated type name, such as .?AVActor@@")
            command.add_argument("--slot-start", type=number, default=0)
            command.add_argument("--slots", type=number, default=16)
    return root


def run(args):
    if hasattr(args, "limit") and not 1 <= args.limit <= 10000:
        raise ValueError("--limit must be 1..10000")
    if (args.raw is None) != (args.start_va is None):
        raise ValueError("--raw and --start-va must be supplied together")
    if args.raw is None and (args.module_base is not None or args.module_size is not None):
        raise ValueError("--module-base and --module-size require --raw")
    if args.raw:
        source = raw_source(
            args.raw, args.start_va, module_base=args.module_base, module_size=args.module_size
        )
    else:
        source = PE(args.file)
    if args.command == "info":
        result = {}
        if isinstance(source, PE):
            result = {
                "sections": source.sections,
                "imports": limited(source.imports.values(), args.limit),
                "exports": limited(source.exports, args.limit),
                "unwind_entry_count": len(source.entries),
            }
    elif args.command == "find":
        result = search(
            source,
            text=args.text,
            encoding=args.encoding,
            pattern=args.pattern,
            value=args.value,
            value_type=args.type,
            limit=args.limit,
            scope={"section": args.section, "start": args.start, "length": args.length},
        )
    elif args.command == "refs":
        result = references(
            source,
            address=args.address,
            displacement=args.displacement,
            kind=args.kind,
            limit=args.limit,
            scope={"section": args.section, "start": args.start, "length": args.length},
        )
    elif args.command == "disasm":
        result = disassemble(
            source, args.address, byte_count=args.bytes, unwind=args.unwind, limit=args.limit
        )
    elif args.command == "data":
        result = read_data(source, args.address, args.type, args.count)
    else:
        result = rtti(source, args.name, slots=args.slots, slot_start=args.slot_start, limit=args.limit)
    report = {
        "tool": {
            "name": "static-byte-inspector",
            "capstone": version("capstone"),
            "pefile": pefile.__version__,
        },
        "command": args.command,
        "source": source.metadata,
        **result,
    }
    if isinstance(source, PE):
        report["pe_warnings"] = source.pe.get_warnings()
    return report


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        report = run(args)
        output = json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False)
    except (OSError, ValueError, struct.error, OverflowError, pefile.PEFormatError, capstone.CsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
