"""Command-line interface for richprint."""

import argparse
import json
import sys
from typing import List, Optional

from .database import load_database
from .parser import parse_file
from .models import ParseResult


def format_entry_line(entry) -> str:
    """Format a single Rich header entry for display."""
    return (
        f"{entry.comp_id:08x} {entry.product_id:4x} {entry.build_version:6d} "
        f"{entry.count:5d}"
        + (f" {entry.description}" if entry.description else "")
    )


def print_result(result: ParseResult) -> None:
    """Print parse result in human-readable format."""
    print(f"Processing {result.filename}")

    if not result.success:
        print(result.error, file=sys.stderr)
        return

    if result.pe_info:
        print(f"Target machine: {result.pe_info.machine_name}")

    if result.rich_header and result.rich_header.entries:
        print("@comp.id   id version count   description")
        for entry in result.rich_header.entries:
            print(format_entry_line(entry))


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="richprint",
        description="Decode and print Rich headers from Windows PE executables.",
        epilog=(
            "Rich headers contain compiler version information embedded by "
            "Microsoft's linker."
        ),
    )

    parser.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help="PE executable file(s) to analyze",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    parser.add_argument(
        "--database", "-d",
        metavar="PATH",
        help="Path to custom comp_id.txt database file",
    )

    parser.add_argument(
        "--version", "-V",
        action="version",
        version="%(prog)s 1.0.0",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for CLI."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.files:
        print(
            "Rich header decoder. Usage:\n\n"
            "  richprint file ...\n\n"
            "Rich headers can be found in executable files, DLLs, "
            "and other binary files\ncreated by Microsoft linker."
        )
        return 0

    # Load database
    db = load_database(args.database)

    results = []
    for filename in args.files:
        result = parse_file(filename, db)
        results.append(result)

    if args.json:
        output = [r.to_dict() for r in results]
        print(json.dumps(output, indent=2))
    else:
        for result in results:
            print_result(result)

    # Return non-zero if any file failed
    return 0 if all(r.success for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
