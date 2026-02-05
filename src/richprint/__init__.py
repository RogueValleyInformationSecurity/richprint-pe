"""
richprint - Decode and print Rich headers from Windows PE executables.

The Rich header is metadata embedded by Microsoft's linker containing
compiler version information (@comp.id records).
"""

from .parser import parse_file, parse_bytes
from .database import load_database, lookup_description, CompilerDatabase
from .models import CompilerEntry, RichHeader, PEInfo, ParseResult
from .constants import (
    MZ_SIGNATURE,
    PE_SIGNATURE,
    RICH_SIGNATURE,
    DANS_SIGNATURE,
    MACHINE_TYPES,
    get_machine_type,
)
from .exceptions import (
    RichPrintError,
    FileOpenError,
    NoMZHeaderError,
    NoPEHeaderError,
    InvalidDOSHeaderError,
    NoRichHeaderError,
    NoDanSTokenError,
    InvalidRichHeaderError,
)

__version__ = "1.0.0"

__all__ = [
    # Main API
    "parse_file",
    "parse_bytes",
    "load_database",
    "lookup_description",
    # Models
    "CompilerEntry",
    "RichHeader",
    "PEInfo",
    "ParseResult",
    "CompilerDatabase",
    # Constants
    "MZ_SIGNATURE",
    "PE_SIGNATURE",
    "RICH_SIGNATURE",
    "DANS_SIGNATURE",
    "MACHINE_TYPES",
    "get_machine_type",
    # Exceptions
    "RichPrintError",
    "FileOpenError",
    "NoMZHeaderError",
    "NoPEHeaderError",
    "InvalidDOSHeaderError",
    "NoRichHeaderError",
    "NoDanSTokenError",
    "InvalidRichHeaderError",
    # Version
    "__version__",
]
