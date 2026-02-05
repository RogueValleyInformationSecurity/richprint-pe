"""Tests for parser module."""

import struct
import pytest

from richprint.parser import (
    read_word,
    read_dword,
    parse_pe_info,
    find_rich_header,
    decode_rich_header,
    parse_bytes,
)
from richprint.constants import (
    MZ_SIGNATURE,
    PE_SIGNATURE,
    RICH_SIGNATURE,
    DANS_SIGNATURE,
)
from richprint.exceptions import (
    NoMZHeaderError,
    NoPEHeaderError,
    InvalidDOSHeaderError,
    NoRichHeaderError,
    NoDanSTokenError,
)


class TestBinaryReading:
    """Tests for binary reading functions."""

    def test_read_word(self):
        """Test 16-bit little-endian reading."""
        data = b"\x4d\x5a"  # MZ signature
        assert read_word(data, 0) == 0x5A4D

    def test_read_word_offset(self):
        """Test reading at offset."""
        data = b"\x00\x00\x34\x12"
        assert read_word(data, 2) == 0x1234

    def test_read_dword(self):
        """Test 32-bit little-endian reading."""
        data = b"\x50\x45\x00\x00"  # PE signature
        assert read_dword(data, 0) == 0x4550

    def test_read_dword_offset(self):
        """Test reading at offset."""
        data = b"\x00\x78\x56\x34\x12"
        assert read_dword(data, 1) == 0x12345678


def create_minimal_pe(
    with_rich_header: bool = True,
    xor_key: int = 0x12345678,
    entries: list = None,
) -> bytes:
    """
    Create a minimal PE file structure for testing.

    Args:
        with_rich_header: Whether to include Rich header.
        xor_key: XOR key for Rich header encoding.
        entries: List of (comp_id, count) tuples for Rich header entries.

    Returns:
        Bytes representing minimal PE structure.
    """
    if entries is None:
        entries = [(0x00E1520D, 10), (0x00DF520D, 1)]

    # DOS Header (64 bytes minimum)
    dos_header = bytearray(64)

    # MZ signature
    struct.pack_into("<H", dos_header, 0, MZ_SIGNATURE)
    # Number of relocations
    struct.pack_into("<H", dos_header, 0x06, 0)
    # Size of header in paragraphs (4 minimum)
    struct.pack_into("<H", dos_header, 0x08, 4)
    # Relocation table offset
    struct.pack_into("<H", dos_header, 0x18, 0x40)

    # Build Rich header if requested
    rich_section = bytearray()
    if with_rich_header:
        # DanS marker (XOR'd)
        rich_section.extend(struct.pack("<I", DANS_SIGNATURE ^ xor_key))
        # 3 padding DWORDs (XOR'd with key)
        for _ in range(3):
            rich_section.extend(struct.pack("<I", xor_key))
        # Entries
        for comp_id, count in entries:
            rich_section.extend(struct.pack("<I", comp_id ^ xor_key))
            rich_section.extend(struct.pack("<I", count ^ xor_key))
        # Rich marker and key
        rich_section.extend(struct.pack("<I", RICH_SIGNATURE))
        rich_section.extend(struct.pack("<I", xor_key))

    # Padding to align PE header
    padding_needed = (16 - (64 + len(rich_section)) % 16) % 16
    padding = b"\x00" * padding_needed

    # PE offset
    pe_offset = 64 + len(rich_section) + padding_needed
    struct.pack_into("<H", dos_header, 0x3C, pe_offset)

    # PE Header
    pe_header = bytearray(24)  # Minimal COFF header
    struct.pack_into("<I", pe_header, 0, PE_SIGNATURE)
    struct.pack_into("<H", pe_header, 4, 0x8664)  # x64 machine type

    return bytes(dos_header) + bytes(rich_section) + padding + bytes(pe_header)


class TestParsePEInfo:
    """Tests for parse_pe_info function."""

    def test_valid_pe(self):
        """Test parsing valid PE structure."""
        data = create_minimal_pe()
        pe_info = parse_pe_info(data)

        assert pe_info.machine_type == 0x8664
        assert pe_info.machine_name == "x64"
        assert pe_info.pe_offset > 0

    def test_no_mz_header(self):
        """Test error on missing MZ signature."""
        data = b"NOT_MZ" + b"\x00" * 100
        with pytest.raises(NoMZHeaderError):
            parse_pe_info(data)

    def test_file_too_small(self):
        """Test error on file too small."""
        data = b"M"
        with pytest.raises(NoMZHeaderError):
            parse_pe_info(data)

    def test_invalid_header_paragraphs(self):
        """Test error on invalid header paragraph count."""
        data = bytearray(create_minimal_pe())
        struct.pack_into("<H", data, 0x08, 2)  # Set to 2 (< 4)
        with pytest.raises(InvalidDOSHeaderError):
            parse_pe_info(bytes(data))

    def test_no_pe_signature(self):
        """Test error on missing PE signature."""
        data = bytearray(create_minimal_pe())
        pe_offset = struct.unpack_from("<H", data, 0x3C)[0]
        struct.pack_into("<I", data, pe_offset, 0xDEADBEEF)  # Invalid signature
        with pytest.raises(NoPEHeaderError):
            parse_pe_info(bytes(data))


class TestFindRichHeader:
    """Tests for find_rich_header function."""

    def test_find_rich_header(self):
        """Test finding Rich header in valid PE."""
        xor_key = 0xABCDEF12
        data = create_minimal_pe(with_rich_header=True, xor_key=xor_key)
        pe_info = parse_pe_info(data)

        rich_offset, dans_offset, found_key = find_rich_header(data, pe_info)

        assert found_key == xor_key
        assert rich_offset > dans_offset
        assert dans_offset >= pe_info.dos_stub_end

    def test_no_rich_header(self):
        """Test error when Rich header is missing."""
        data = create_minimal_pe(with_rich_header=False)
        pe_info = parse_pe_info(data)

        with pytest.raises(NoRichHeaderError):
            find_rich_header(data, pe_info)


class TestDecodeRichHeader:
    """Tests for decode_rich_header function."""

    def test_decode_entries(self):
        """Test decoding Rich header entries."""
        entries = [(0x00E1520D, 10), (0x00DF520D, 1), (0x00DE520D, 1)]
        xor_key = 0x98765432
        data = create_minimal_pe(
            with_rich_header=True, xor_key=xor_key, entries=entries
        )
        pe_info = parse_pe_info(data)
        rich_offset, dans_offset, key = find_rich_header(data, pe_info)

        rich_header = decode_rich_header(data, rich_offset, dans_offset, key)

        assert len(rich_header.entries) == len(entries)
        assert rich_header.xor_key == xor_key

        for i, (comp_id, count) in enumerate(entries):
            assert rich_header.entries[i].comp_id == comp_id
            assert rich_header.entries[i].count == count
            assert rich_header.entries[i].product_id == comp_id >> 16
            assert rich_header.entries[i].build_version == comp_id & 0xFFFF


class TestParseBytes:
    """Tests for parse_bytes function."""

    def test_parse_complete(self):
        """Test complete parsing workflow."""
        entries = [(0x00E1520D, 5)]
        data = create_minimal_pe(with_rich_header=True, entries=entries)

        result = parse_bytes(data)

        assert result.success
        assert result.error is None
        assert result.pe_info is not None
        assert result.pe_info.machine_name == "x64"
        assert result.rich_header is not None
        assert len(result.rich_header.entries) == 1
        assert result.rich_header.entries[0].comp_id == 0x00E1520D
        assert result.rich_header.entries[0].count == 5

    def test_parse_no_rich_header(self):
        """Test parsing PE without Rich header."""
        data = create_minimal_pe(with_rich_header=False)

        result = parse_bytes(data)

        assert not result.success
        assert "not found" in result.error.lower()
        assert result.pe_info is not None  # PE info should still be available

    def test_parse_invalid_file(self):
        """Test parsing invalid file."""
        data = b"This is not a PE file"

        result = parse_bytes(data)

        assert not result.success
        assert result.error is not None

    def test_to_dict(self):
        """Test ParseResult to_dict conversion."""
        entries = [(0x00E1520D, 3)]
        data = create_minimal_pe(with_rich_header=True, entries=entries)

        result = parse_bytes(data, filename="test.exe")
        d = result.to_dict()

        assert d["filename"] == "test.exe"
        assert d["success"] is True
        assert "pe_info" in d
        assert "rich_header" in d
        assert len(d["rich_header"]["entries"]) == 1
