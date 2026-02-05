"""Tests for database module."""

import os
import tempfile
import pytest

from richprint.database import load_database, lookup_description


class TestLoadDatabase:
    """Tests for load_database function."""

    def test_load_bundled_database(self):
        """Test loading bundled comp_id.txt database."""
        db = load_database()

        # Should have loaded entries
        assert len(db) > 0

        # Check for known entries
        assert 0x00010000 in db  # Unmarked objects
        assert "[---]" in db[0x00010000]

    def test_load_custom_database(self):
        """Test loading custom database file."""
        content = """\
# Test database
00010000 [---] Test entry one
00020000 [C++] Test entry two
00030000 [ C ] Test entry three
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write(content)
            temp_path = f.name

        try:
            db = load_database(temp_path)
            assert len(db) == 3
            assert db[0x00010000] == "[---] Test entry one"
            assert db[0x00020000] == "[C++] Test entry two"
            assert db[0x00030000] == "[ C ] Test entry three"
        finally:
            os.unlink(temp_path)

    def test_skip_comments(self):
        """Test that comments are skipped."""
        content = """\
# Full line comment
00010000 [---] Entry with comment # trailing comment
# Another comment
00020000 [C++] Clean entry
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write(content)
            temp_path = f.name

        try:
            db = load_database(temp_path)
            assert len(db) == 2
            # Trailing comment should be stripped
            assert db[0x00010000] == "[---] Entry with comment"
            assert db[0x00020000] == "[C++] Clean entry"
        finally:
            os.unlink(temp_path)

    def test_skip_short_lines(self):
        """Test that lines shorter than 8 chars are skipped."""
        content = """\
short
00010000 [---] Valid entry
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write(content)
            temp_path = f.name

        try:
            db = load_database(temp_path)
            assert len(db) == 1
        finally:
            os.unlink(temp_path)

    def test_skip_duplicates(self):
        """Test that duplicate entries keep first value."""
        content = """\
00010000 [---] First entry
00010000 [C++] Duplicate entry
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write(content)
            temp_path = f.name

        try:
            db = load_database(temp_path)
            assert len(db) == 1
            assert db[0x00010000] == "[---] First entry"
        finally:
            os.unlink(temp_path)

    def test_nonexistent_file(self):
        """Test loading nonexistent file returns empty dict."""
        db = load_database("/nonexistent/path/to/file.txt")
        assert db == {}


class TestLookupDescription:
    """Tests for lookup_description function."""

    def test_exact_match(self):
        """Test exact comp_id match."""
        db = {
            0x00E1520D: "[C++] VS2013 build 21005",
            0x00E1: "Generic C++ compiler",
        }

        result = lookup_description(db, 0x00E1520D, 0x00E1)
        assert result == "[C++] VS2013 build 21005"

    def test_fallback_to_product_id(self):
        """Test fallback to product_id when exact match not found."""
        db = {
            0x00E1: "Generic C++ compiler",
        }

        result = lookup_description(db, 0x00E1520D, 0x00E1)
        assert result == "Generic C++ compiler"

    def test_no_match(self):
        """Test empty string when no match found."""
        db = {
            0x00FF: "Some other entry",
        }

        result = lookup_description(db, 0x00E1520D, 0x00E1)
        assert result == ""

    def test_empty_database(self):
        """Test lookup in empty database."""
        db = {}

        result = lookup_description(db, 0x00E1520D, 0x00E1)
        assert result == ""
