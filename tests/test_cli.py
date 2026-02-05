"""Tests for CLI module."""

import json
import os
import struct
import tempfile
import pytest

from richprint.cli import main, create_parser, format_entry_line
from richprint.models import CompilerEntry
from richprint.constants import MZ_SIGNATURE, PE_SIGNATURE, RICH_SIGNATURE, DANS_SIGNATURE


def create_test_pe(xor_key: int = 0x12345678) -> bytes:
    """Create a minimal PE file for CLI testing."""
    entries = [(0x00E1520D, 10)]

    # DOS Header (64 bytes minimum)
    dos_header = bytearray(64)
    struct.pack_into("<H", dos_header, 0, MZ_SIGNATURE)
    struct.pack_into("<H", dos_header, 0x06, 0)
    struct.pack_into("<H", dos_header, 0x08, 4)
    struct.pack_into("<H", dos_header, 0x18, 0x40)

    # Rich header
    rich_section = bytearray()
    rich_section.extend(struct.pack("<I", DANS_SIGNATURE ^ xor_key))
    for _ in range(3):
        rich_section.extend(struct.pack("<I", xor_key))
    for comp_id, count in entries:
        rich_section.extend(struct.pack("<I", comp_id ^ xor_key))
        rich_section.extend(struct.pack("<I", count ^ xor_key))
    rich_section.extend(struct.pack("<I", RICH_SIGNATURE))
    rich_section.extend(struct.pack("<I", xor_key))

    # Padding
    padding_needed = (16 - (64 + len(rich_section)) % 16) % 16
    padding = b"\x00" * padding_needed

    pe_offset = 64 + len(rich_section) + padding_needed
    struct.pack_into("<H", dos_header, 0x3C, pe_offset)

    # PE Header
    pe_header = bytearray(24)
    struct.pack_into("<I", pe_header, 0, PE_SIGNATURE)
    struct.pack_into("<H", pe_header, 4, 0x8664)

    return bytes(dos_header) + bytes(rich_section) + padding + bytes(pe_header)


class TestFormatEntryLine:
    """Tests for format_entry_line function."""

    def test_format_with_description(self):
        """Test formatting entry with description."""
        entry = CompilerEntry(
            comp_id=0x00E1520D,
            product_id=0x00E1,
            build_version=0x520D,
            count=10,
            description="[C++] VS2013 build 21005",
        )
        line = format_entry_line(entry)

        assert "00e1520d" in line
        assert "e1" in line
        assert "21005" in line  # 0x520D = 21005
        assert "10" in line
        assert "[C++] VS2013 build 21005" in line

    def test_format_without_description(self):
        """Test formatting entry without description."""
        entry = CompilerEntry(
            comp_id=0x00E1520D,
            product_id=0x00E1,
            build_version=0x520D,
            count=5,
            description="",
        )
        line = format_entry_line(entry)

        assert "00e1520d" in line
        assert line.strip().endswith("5")


class TestCreateParser:
    """Tests for argument parser."""

    def test_parser_basic(self):
        """Test basic argument parsing."""
        parser = create_parser()
        args = parser.parse_args(["file1.exe", "file2.dll"])

        assert args.files == ["file1.exe", "file2.dll"]
        assert not args.json
        assert args.database is None

    def test_parser_json_flag(self):
        """Test --json flag."""
        parser = create_parser()
        args = parser.parse_args(["--json", "file.exe"])

        assert args.json
        assert args.files == ["file.exe"]

    def test_parser_database_option(self):
        """Test --database option."""
        parser = create_parser()
        args = parser.parse_args(["--database", "/path/to/db.txt", "file.exe"])

        assert args.database == "/path/to/db.txt"

    def test_parser_short_flags(self):
        """Test short flag variants."""
        parser = create_parser()
        args = parser.parse_args(["-d", "/path/db.txt", "file.exe"])

        assert args.database == "/path/db.txt"


class TestMain:
    """Tests for main CLI function."""

    def test_no_args_shows_usage(self, capsys):
        """Test that no arguments shows usage message."""
        result = main([])
        captured = capsys.readouterr()

        assert result == 0
        assert "Rich header decoder" in captured.out

    def test_process_valid_file(self, capsys):
        """Test processing a valid PE file."""
        with tempfile.NamedTemporaryFile(
            suffix=".exe", delete=False
        ) as f:
            f.write(create_test_pe())
            temp_path = f.name

        try:
            result = main([temp_path])
            captured = capsys.readouterr()

            assert result == 0
            assert "Processing" in captured.out
            assert "Target machine: x64" in captured.out
            assert "@comp.id" in captured.out
        finally:
            os.unlink(temp_path)

    def test_process_invalid_file(self, capsys):
        """Test processing an invalid file."""
        with tempfile.NamedTemporaryFile(
            suffix=".exe", delete=False
        ) as f:
            f.write(b"Not a PE file")
            temp_path = f.name

        try:
            result = main([temp_path])
            captured = capsys.readouterr()

            assert result == 1  # Non-zero for failure
            assert "No MZ header" in captured.err
        finally:
            os.unlink(temp_path)

    def test_json_output(self, capsys):
        """Test JSON output format."""
        with tempfile.NamedTemporaryFile(
            suffix=".exe", delete=False
        ) as f:
            f.write(create_test_pe())
            temp_path = f.name

        try:
            result = main(["--json", temp_path])
            captured = capsys.readouterr()

            # Should be valid JSON
            data = json.loads(captured.out)
            assert isinstance(data, list)
            assert len(data) == 1
            assert data[0]["success"] is True
            assert "pe_info" in data[0]
            assert "rich_header" in data[0]
        finally:
            os.unlink(temp_path)

    def test_multiple_files(self, capsys):
        """Test processing multiple files."""
        files = []
        try:
            for i in range(2):
                f = tempfile.NamedTemporaryFile(
                    suffix=".exe", delete=False
                )
                f.write(create_test_pe(xor_key=0x12345678 + i))
                f.close()
                files.append(f.name)

            result = main(files)
            captured = capsys.readouterr()

            assert result == 0
            # Should see "Processing" for each file
            assert captured.out.count("Processing") == 2
        finally:
            for path in files:
                os.unlink(path)

    def test_nonexistent_file(self, capsys):
        """Test error handling for nonexistent file."""
        result = main(["/nonexistent/path/file.exe"])
        captured = capsys.readouterr()

        assert result == 1
        # Error message goes to stderr
        assert "Failed to open file" in captured.err or "error" in captured.err.lower()
