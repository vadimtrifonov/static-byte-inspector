---
name: static-byte-inspector
description: Disassemble and search AMD64 PE files and raw byte dumps offline. Find strings, signatures, candidate references, and MSVC vtables.
---

# Static Byte Inspector

Use this skill directory as the working directory.
Commands read files and print JSON to stdout.

## Setup

```powershell
mise trust mise.toml
mise install
mise run setup
```

## Sources and addresses

Every command requires exactly one source:

| Source | Meaning |
|---|---|
| `--file PATH` | AMD64 PE32+ executable or DLL |
| `--raw PATH --start-va N` | Raw AMD64 bytes; N is the VA of the first byte |

With `--module-base N --module-size N`, raw sources accept `rva:` addresses and report RVAs.
These define the module's address range, not the available byte range; addresses outside that module have no RVA.

Addresses require a prefix:

| Address | Interpretation |
|---|---|
| `rva:0x1000` | Relative to the PE preferred image base or the supplied raw `--module-base` |
| `va:0x140001000` | Preferred-image VA for a PE file; absolute VA for raw bytes |
| `offset:0x400` | Offset in the input file |

Numbers accept decimal or `0x` notation.
PE RVA/VA reads must lie within the headers or one section's raw data; uninitialized section tails have no file bytes.
Offset-based data reads can access unmapped file bytes, such as overlays; disassembly requires a mapped VA.

Packed or encrypted on-disk code can produce meaningless `disasm` output and few or no `refs` matches without an error.
Use bytes captured after unpacking/decryption; a `.bind` section alone does not establish encryption.

## PE metadata

```powershell
mise run inspector -- info --file "C:\Path\To\image.exe" --limit 50
```

Imports identify IAT cells, including delay imports.

## Search

```powershell
mise run inspector -- find --file "C:\Path\To\image.exe" --text "SettingName" --encoding both
mise run inspector -- find --file "C:\Path\To\image.exe" --pattern "48 8D ?? ?? ?? ?? ??" --section .text
mise run inspector -- find --file "C:\Path\To\image.exe" --value 0x1234 --type u32
```

Text searches are literal and case-sensitive, with `ascii` (default), `utf-16le`, or `both`.
Signatures use full byte pairs and `??` wildcards, with at least one exact byte.
Numeric searches use little-endian encoding.
Search totals count overlapping matches within the selected scope.

Searches include the whole file by default, including overlays; unmapped hits have an offset but null RVA/VA.
Use `--section NAME` or `--start rva:0x1000 --length 0x400` to restrict `find` and `refs`.

## References

```powershell
mise run inspector -- refs rva:0x123450 --file "C:\Path\To\image.exe" --kind call
mise run inspector -- refs rva:0x456780 --file "C:\Path\To\image.exe" --kind memory
mise run inspector -- refs rva:0x123450 --file "C:\Path\To\image.exe" --kind pointer
mise run inspector -- refs --displacement 0x3F4 --file "C:\Path\To\image.exe"
```

`--kind` selects `all` (default), `call`, `branch`, `memory`, or `pointer`.
Calls and branches are direct relative transfers; memory references use RIP/EIP-relative operands.
Pointer searches match 64-bit addresses throughout the selected scope, including unaligned values.
Register-dependent transfers, computed addresses, and absolute-address instruction encodings are not resolved by these searches.

For calls or jumps through an IAT cell, search that cell with `--kind memory`.
Direct calls through an import thunk instead reference the thunk's address.

Code searches scan executable PE sections, or the supplied raw bytes.
`--displacement` accepts a nonzero signed 32-bit memory displacement.
Any base register matches, including `rsp` and `rbp`.
Displacements in -128..127 require a scan scope of at most 1 MiB.

| `boundary` | Evidence |
|---|---|
| `unwind_linear` | Instruction starts on a boundary decoded from its containing unwind entry |
| `candidate_no_unwind` | No unwind metadata is available for this candidate |
| `candidate_after_decode_gap` | Decoding from the unwind entry stopped before the candidate |
| `candidate_verification_limit` | The unwind entry exceeds the 1 MiB decoding budget |
| `data_candidate` | Matching pointer bytes, not an instruction |

Candidates inside another instruction in the selected unwind decoding are rejected.
Code matches are deduplicated by operand-field location and reference kind.
Without a verified boundary, a prefix heuristic selects one start; it can omit a genuine prefix or include a byte from the preceding instruction.

## Disassembly

```powershell
mise run inspector -- disasm rva:0x123450 --file "C:\Path\To\image.exe" --bytes 256
mise run inspector -- disasm rva:0x123480 --file "C:\Path\To\image.exe" --unwind --limit 300
mise run inspector -- disasm offset:0 --raw "$env:TEMP\text.bin" --start-va 0x7FF600001000 --bytes 128
mise run inspector -- disasm rva:0x1000 --raw "$env:TEMP\code.bin" --start-va 0x7FF600000FE0 `
  --module-base 0x7FF600000000 --module-size 0x4000000
```

A raw range can begin mid-instruction; request a known instruction address.

Decoding is linear, including bytes after branches and returns.
References are annotated with available strings and import names.

By default, decoding uses up to 256 bytes from the requested address, ending at the current PE header/section or raw byte range.
`--bytes N` requests exactly N bytes (1..1,048,576); unavailable bytes are an error.
`--unwind` selects the containing PE unwind entry and adjacent entries with the same chained root.
The combined range must fit in 1 MiB.
Unwind entries can represent parts of a function; nonadjacent parents are listed in the chain but are not joined into the disassembly.

`stop_reason` is `range_end`, `output_limit`, or `invalid_or_truncated_instruction`.

## Data and pointer tables

```powershell
mise run inspector -- data rva:0x456780 --file "C:\Path\To\image.exe" --type pointer --count 16
mise run inspector -- data offset:0 --raw "$env:TEMP\values.bin" --start-va 0 --type f32 --count 8
```

Types: `u8/i8/u16/i16/u32/i32/u64/i64/f32/f64/pointer`.
All are little-endian; pointers are eight bytes.
Defaults are `u8` and 16 elements, with a maximum of 4096.
Nonfinite floats are strings such as `nan` or `inf` to keep the output valid JSON.

## MSVC x64 RTTI

```powershell
mise run inspector -- rtti '.?AVActor@@' --file "C:\Path\To\image.exe" --slots 16
mise run inspector -- rtti '.?AVActor@@' --file "C:\Path\To\image.exe" --slot-start 213 --slots 1
```

Requires a PE file and an exact decorated class or struct name.
Supports image-relative complete-object locators with signature 1.
The primary vtable's `subobject_offset` is `0x0`.

`--slot-start` is zero-based (0..65535); `--slots` defaults to 16 and accepts 1..1024.
Reading stops at the requested count, unavailable bytes, or a destination outside executable PE sections.
These stops describe the read, not the vtable's length.

## Output limits and errors

Commands with `--limit` accept 1..10000, defaulting to 100.
`find`, `refs`, and `rtti` report total matches even when the displayed results are truncated.
For `info`, the limit applies separately to imports and exports; sections are listed in full.
Disassembly stops at its instruction limit instead of counting the remaining instructions.

Input and range errors return nonzero with a diagnostic on stderr and no JSON output.
Incomplete decoding is reported by `stop_reason` and returns zero.
