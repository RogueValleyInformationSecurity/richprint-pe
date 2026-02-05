"""Core PE/Rich header parsing logic."""

import struct
from typing import BinaryIO, List, Optional, Tuple

from .constants import (
    MZ_SIGNATURE,
    PE_SIGNATURE,
    RICH_SIGNATURE,
    DANS_SIGNATURE,
    DOS_NUM_RELOCS_OFFSET,
    DOS_HEADER_PARA_OFFSET,
    DOS_RELOC_OFFSET,
    DOS_PE_OFFSET,
    PE_MACHINE_OFFSET,
    get_machine_type,
)
from .database import CompilerDatabase, lookup_description
from .exceptions import (
    FileOpenError,
    NoMZHeaderError,
    NoPEHeaderError,
    InvalidDOSHeaderError,
    NoRichHeaderError,
    NoDanSTokenError,
    InvalidRichHeaderError,
)
from .models import CompilerEntry, RichHeader, PEInfo, ParseResult


def read_word(data: bytes, offset: int) -> int:
    """Read unsigned 16-bit little-endian value."""
    return struct.unpack_from("<H", data, offset)[0]


def read_dword(data: bytes, offset: int) -> int:
    """Read unsigned 32-bit little-endian value."""
    return struct.unpack_from("<I", data, offset)[0]


def parse_pe_info(data: bytes) -> PEInfo:
    """
    Parse basic PE information from file data.

    Args:
        data: File contents as bytes.

    Returns:
        PEInfo with machine type, PE offset, and DOS stub end offset.

    Raises:
        NoMZHeaderError: If MZ signature not found.
        InvalidDOSHeaderError: If DOS header values are invalid.
        NoPEHeaderError: If PE signature not found.
    """
    # Check MZ header
    if len(data) < 2:
        raise NoMZHeaderError("File too small for MZ header")

    mz = read_word(data, 0)
    if mz != MZ_SIGNATURE:
        raise NoMZHeaderError(f"No MZ header - magic is: 0x{mz:x}")

    # Read DOS header metrics
    if len(data) < 0x40:
        raise InvalidDOSHeaderError("File too small for DOS header")

    num_relocs = read_word(data, DOS_NUM_RELOCS_OFFSET)
    header_para = read_word(data, DOS_HEADER_PARA_OFFSET)

    if header_para < 4:
        raise InvalidDOSHeaderError(
            f"Too few paragraphs in DOS header: {header_para}, not a PE executable"
        )

    reloc_offset = read_word(data, DOS_RELOC_OFFSET)
    pe_offset = read_word(data, DOS_PE_OFFSET)

    if pe_offset < header_para * 16:
        raise InvalidDOSHeaderError(
            f"PE offset is too small: {pe_offset}, not a PE executable"
        )

    # Check PE signature
    if len(data) < pe_offset + 6:
        raise NoPEHeaderError("File too small for PE header")

    pe_sig = read_dword(data, pe_offset)
    if pe_sig != PE_SIGNATURE:
        raise NoPEHeaderError(
            f"No PE header signature: 0x{pe_sig:x}, not a PE executable"
        )

    # Get machine type
    machine_type = read_word(data, pe_offset + PE_MACHINE_OFFSET)
    machine_name = get_machine_type(machine_type)

    # Calculate DOS stub end offset
    dos_stub_end = reloc_offset
    if num_relocs > 0:
        dos_stub_end += 4 * num_relocs

    # Align to 16-byte paragraph boundary
    if dos_stub_end % 16:
        dos_stub_end += 16 - (dos_stub_end % 16)

    return PEInfo(
        machine_type=machine_type,
        machine_name=machine_name,
        pe_offset=pe_offset,
        dos_stub_end=dos_stub_end,
    )


def find_rich_header(data: bytes, pe_info: PEInfo) -> Tuple[int, int, int]:
    """
    Find Rich header markers and XOR key.

    Args:
        data: File contents as bytes.
        pe_info: Parsed PE info with search boundaries.

    Returns:
        Tuple of (rich_offset, dans_offset, xor_key).

    Raises:
        NoRichHeaderError: If Rich signature not found.
        NoDanSTokenError: If DanS token not found.
        InvalidRichHeaderError: If header structure is invalid.
    """
    start = pe_info.dos_stub_end
    end = pe_info.pe_offset

    # Search for "Rich" signature
    rich_offset = -1
    for i in range(start, end, 4):
        if i + 4 > len(data):
            break
        val = read_dword(data, i)
        if val == RICH_SIGNATURE:
            rich_offset = i
            break

    if rich_offset == -1:
        raise NoRichHeaderError("Rich header not found")

    # XOR key is immediately after "Rich"
    if rich_offset + 8 > len(data):
        raise InvalidRichHeaderError("File truncated after Rich signature")

    xor_key = read_dword(data, rich_offset + 4)

    # Search for "DanS" signature (XOR'd with key)
    dans_offset = -1
    target = DANS_SIGNATURE ^ xor_key
    for i in range(start, end, 4):
        if i + 4 > len(data):
            break
        val = read_dword(data, i)
        if val == target:
            dans_offset = i
            break

    if dans_offset == -1:
        raise NoDanSTokenError("Rich header's DanS token not found")

    # Validate end offset doesn't run into PE header
    end_offset = rich_offset + 8  # Rich + key
    if end_offset > pe_info.pe_offset:
        raise InvalidRichHeaderError(
            f"Calculated end offset runs into PE header: 0x{end_offset:x}"
        )

    return rich_offset, dans_offset, xor_key


def decode_rich_header(
    data: bytes,
    rich_offset: int,
    dans_offset: int,
    xor_key: int,
    db: Optional[CompilerDatabase] = None,
) -> RichHeader:
    """
    Decode Rich header entries.

    Args:
        data: File contents as bytes.
        rich_offset: File offset of Rich marker.
        dans_offset: File offset of DanS marker.
        xor_key: XOR key for decoding.
        db: Optional compiler database for descriptions.

    Returns:
        RichHeader with decoded entries.
    """
    entries: List[CompilerEntry] = []

    # Entries start at DanS + 16 (skip DanS + 3 padding DWORDs)
    # Entries end at Rich - 8 (stop before last empty entry)
    start = dans_offset + 16
    end = rich_offset

    for pos in range(start, end, 8):
        if pos + 8 > len(data):
            break

        # Read and decode version and count
        ver_raw = read_dword(data, pos)
        count_raw = read_dword(data, pos + 4)

        ver = ver_raw ^ xor_key
        count = count_raw ^ xor_key

        # Extract product_id and build_version
        product_id = ver >> 16
        build_version = ver & 0xFFFF

        # Look up description
        description = ""
        if db is not None:
            description = lookup_description(db, ver, product_id)

        entries.append(CompilerEntry(
            comp_id=ver,
            product_id=product_id,
            build_version=build_version,
            count=count,
            description=description,
        ))

    return RichHeader(
        xor_key=xor_key,
        entries=entries,
        dans_offset=dans_offset,
        rich_offset=rich_offset,
    )


def parse_file(
    filename: str,
    db: Optional[CompilerDatabase] = None,
) -> ParseResult:
    """
    Parse Rich header from a PE file.

    Args:
        filename: Path to PE file.
        db: Optional compiler database for descriptions.

    Returns:
        ParseResult with parsed data or error information.
    """
    result = ParseResult(filename=filename)

    try:
        with open(filename, "rb") as f:
            data = f.read()
    except (IOError, OSError) as e:
        result.error = f"Failed to open file: {e}"
        return result

    try:
        # Parse PE info
        pe_info = parse_pe_info(data)
        result.pe_info = pe_info

        # Find Rich header
        rich_offset, dans_offset, xor_key = find_rich_header(data, pe_info)

        # Decode entries
        rich_header = decode_rich_header(
            data, rich_offset, dans_offset, xor_key, db
        )
        result.rich_header = rich_header
        result.success = True

    except (
        NoMZHeaderError,
        NoPEHeaderError,
        InvalidDOSHeaderError,
        NoRichHeaderError,
        NoDanSTokenError,
        InvalidRichHeaderError,
    ) as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"Unexpected error: {e}"

    return result


def parse_bytes(
    data: bytes,
    db: Optional[CompilerDatabase] = None,
    filename: str = "<bytes>",
) -> ParseResult:
    """
    Parse Rich header from raw bytes.

    Args:
        data: PE file contents as bytes.
        db: Optional compiler database for descriptions.
        filename: Optional filename for result.

    Returns:
        ParseResult with parsed data or error information.
    """
    result = ParseResult(filename=filename)

    try:
        # Parse PE info
        pe_info = parse_pe_info(data)
        result.pe_info = pe_info

        # Find Rich header
        rich_offset, dans_offset, xor_key = find_rich_header(data, pe_info)

        # Decode entries
        rich_header = decode_rich_header(
            data, rich_offset, dans_offset, xor_key, db
        )
        result.rich_header = rich_header
        result.success = True

    except (
        NoMZHeaderError,
        NoPEHeaderError,
        InvalidDOSHeaderError,
        NoRichHeaderError,
        NoDanSTokenError,
        InvalidRichHeaderError,
    ) as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"Unexpected error: {e}"

    return result
