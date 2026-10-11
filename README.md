# Static Byte Inspector

Static Byte Inspector is a command-line tool for inspecting x86-64 code and data in PE files and raw byte files.
It searches for strings, byte patterns, and references, and displays disassembly or data at selected addresses.
Inspection is offline and read-only.

## Input files

A **PE file** supplies bytes from a Windows x64 executable or DLL, along with its sections, imports, exports, and unwind metadata.
Addresses in the file use its preferred image base, which can differ from the address where it is loaded at runtime.

A **raw byte file** contains bytes without headers, such as a saved memory range.
Its starting virtual address must be supplied so instruction targets and references can be calculated.
An optional module base and size enable module-relative addresses (RVAs).

## Commands

| Command | Input | Output |
|---|---|---|
| `info` | Any supported input file | Source identity and available PE metadata |
| `find` | String, byte pattern, or number | Matching locations and match counts |
| `refs` | Address or memory-operand offset | Candidate code references, stored pointers, or matching memory operands |
| `disasm` | Address and range | Instructions with branch targets and data-reference annotations |
| `data` | Address and data type | Typed values or pointer targets |
| `rtti` | MSVC C++ type name in a PE file | Candidate virtual function tables, subobject offsets, and selected slots |

Results are JSON and include source hashes to identify the input.
Reference searches distinguish validated instruction boundaries from unverified byte matches.

Disassembly can use an explicit byte count or ranges from PE unwind metadata, which Windows uses for exception handling.
These ranges can cover parts of functions rather than whole functions.

## Getting started

Setup and development tasks use [mise](https://mise.jdx.dev/).
See [SKILL.md](SKILL.md) for setup and operating commands.

## Development

Run the unit tests with `mise run test`.
Check the tool's Python formatting and lint rules with `mise run check`.
