"""Compiler ID database loading and lookup."""

import importlib.resources
from typing import Dict, Optional

# Type alias for the database
CompilerDatabase = Dict[int, str]


def load_database(path: Optional[str] = None) -> CompilerDatabase:
    """
    Load compiler ID database from file.

    Args:
        path: Path to comp_id.txt file. If None, uses bundled database.

    Returns:
        Dictionary mapping comp.id values to descriptions.
    """
    descriptions: CompilerDatabase = {}

    if path is None:
        # Use bundled database
        try:
            # Python 3.9+
            files = importlib.resources.files("richprint.data")
            content = (files / "comp_id.txt").read_text(encoding="utf-8")
        except AttributeError:
            # Python 3.8 fallback
            import pkg_resources
            content = pkg_resources.resource_string(
                "richprint.data", "comp_id.txt"
            ).decode("utf-8")
        lines = content.splitlines()
    else:
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (IOError, OSError):
            return descriptions

    for line in lines:
        line = line.rstrip("\n\r")

        # Remove trailing comments
        comment_pos = line.rfind("#")
        if comment_pos != -1:
            # Trim trailing spaces before comment
            while comment_pos > 0 and line[comment_pos - 1] == " ":
                comment_pos -= 1
            line = line[:comment_pos]

        # Skip empty lines and comment-only lines
        if len(line) <= 8 or line.startswith("#"):
            continue

        # Parse: <hex_id> <description>
        try:
            hex_part = line[:8]
            comp_id = int(hex_part, 16)
            desc = line[9:] if len(line) > 9 else ""

            # Skip duplicates (keep first)
            if comp_id not in descriptions:
                descriptions[comp_id] = desc
        except ValueError:
            continue

    return descriptions


def lookup_description(
    db: CompilerDatabase, comp_id: int, product_id: int
) -> str:
    """
    Look up description for a compiler entry.

    First tries exact comp_id match, then falls back to product_id only.

    Args:
        db: Compiler database dictionary.
        comp_id: Full compiler ID (product_id << 16 | build_version).
        product_id: Product ID (high 16 bits of comp_id).

    Returns:
        Description string, or empty string if not found.
    """
    # Try exact match first
    if comp_id in db:
        return db[comp_id]
    # Fall back to product_id only
    if product_id in db:
        return db[product_id]
    return ""
