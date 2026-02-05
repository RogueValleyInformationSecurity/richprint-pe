# richprint

A Python tool to decode and print compiler information stored in the Rich Header of Windows PE executables.

## Installation

```bash
pip install richprint-pe
```

Or run directly without installing using [uv](https://docs.astral.sh/uv/):

```bash
uvx richprint-pe notepad.exe
```

## What is the Rich Header?

The Rich Header is a section of binary data created by Microsoft's linker, located between the DOS stub and PE header in Windows executables. It contains a list of compiler/tool IDs (@comp.id) used to build the executable, allowing identification of exact compiler versions down to build numbers.

The data is XOR-encoded, with "Rich" being the only readable marker. Files created by non-Microsoft linkers will not have this header.

For technical details, see [Daniel Pistelli's article](http://www.ntcore.com/files/richsign.htm).

## Usage

### Command Line

```bash
# Analyze one or more files
richprint notepad.exe
richprint file1.exe file2.dll file3.sys

# JSON output
richprint --json notepad.exe

# Use custom compiler ID database
richprint --database /path/to/comp_id.txt notepad.exe
```

### Python API

```python
from richprint import parse_file, load_database

# Load the bundled compiler ID database
db = load_database()

# Parse a PE file
result = parse_file("notepad.exe", db)

if result.success:
    print(f"Machine: {result.pe_info.machine_name}")
    print(f"XOR Key: 0x{result.rich_header.xor_key:08x}")
    for entry in result.rich_header.entries:
        print(f"  {entry.comp_id:08x} {entry.description}")
else:
    print(f"Error: {result.error}")
```

## Output Format

```
Processing notepad.exe
Target machine: x64
@comp.id   id version count   description
00e1520d   e1  21005    10   [C++] VS2013 build 21005
00df520d   df  21005     1   [ASM] VS2013 build 21005
00de520d   de  21005     1   [LNK] VS2013 build 21005
```

## Compiler ID Database

The bundled `comp_id.txt` database maps compiler IDs to human-readable descriptions. The format supports:

- `[ C ]` - C compiler
- `[C++]` - C++ compiler
- `[ASM]` - Assembler
- `[LNK]` - Linker
- `[RES]` - Resource converter
- `[IMP]` / `[EXP]` - DLL import/export records
- And many more...

## Suppressing Rich Headers

To prevent Microsoft tools from emitting this header, use the undocumented linker option:
```
/emittoolversioninfo:no
```

Available since VS2019 Update 11.

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.

## Credits

Original C++ implementation and compiler ID database by [dishather](https://github.com/dishather/richprint).
