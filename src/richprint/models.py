"""Data models for richprint."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CompilerEntry:
    """A single entry from the Rich header."""
    comp_id: int  # Full @comp.id value (product_id << 16 | build_version)
    product_id: int  # Product/tool identifier (high 16 bits)
    build_version: int  # Build version number (low 16 bits)
    count: int  # Number of objects with this comp.id
    description: str = ""  # Human-readable description from database


@dataclass
class RichHeader:
    """Parsed Rich header data."""
    xor_key: int  # XOR key used to encode the header
    entries: List[CompilerEntry] = field(default_factory=list)
    dans_offset: int = 0  # File offset of DanS marker
    rich_offset: int = 0  # File offset of Rich marker


@dataclass
class PEInfo:
    """Basic PE file information."""
    machine_type: int  # Machine type value
    machine_name: str  # Human-readable machine name
    pe_offset: int  # File offset of PE header
    dos_stub_end: int  # End of DOS stub (start of search area)


@dataclass
class ParseResult:
    """Complete result of parsing a PE file."""
    filename: str
    success: bool = False
    error: Optional[str] = None
    pe_info: Optional[PEInfo] = None
    rich_header: Optional[RichHeader] = None

    def to_dict(self) -> dict:
        """Convert result to dictionary for JSON serialization."""
        result = {
            "filename": self.filename,
            "success": self.success,
        }
        if self.error:
            result["error"] = self.error
        if self.pe_info:
            result["pe_info"] = {
                "machine_type": self.pe_info.machine_type,
                "machine_name": self.pe_info.machine_name,
                "pe_offset": self.pe_info.pe_offset,
            }
        if self.rich_header:
            result["rich_header"] = {
                "xor_key": f"0x{self.rich_header.xor_key:08x}",
                "entries": [
                    {
                        "comp_id": f"0x{e.comp_id:08x}",
                        "product_id": e.product_id,
                        "build_version": e.build_version,
                        "count": e.count,
                        "description": e.description,
                    }
                    for e in self.rich_header.entries
                ],
            }
        return result
