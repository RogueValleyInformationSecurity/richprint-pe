"""Custom exceptions for richprint."""


class RichPrintError(Exception):
    """Base exception for richprint errors."""
    pass


class FileOpenError(RichPrintError):
    """Failed to open or read file."""
    pass


class NoMZHeaderError(RichPrintError):
    """File does not have MZ (DOS) header signature."""
    pass


class NoPEHeaderError(RichPrintError):
    """File does not have valid PE header."""
    pass


class InvalidDOSHeaderError(RichPrintError):
    """DOS header has invalid values."""
    pass


class NoRichHeaderError(RichPrintError):
    """Rich header not found in file."""
    pass


class NoDanSTokenError(RichPrintError):
    """Rich header's DanS token not found."""
    pass


class InvalidRichHeaderError(RichPrintError):
    """Rich header structure is invalid."""
    pass
