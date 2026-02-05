"""Magic numbers and constants for PE/Rich header parsing."""

# Signature magic values
MZ_SIGNATURE = 0x5A4D  # "MZ" - DOS executable signature
PE_SIGNATURE = 0x4550  # "PE\0\0" - PE header signature
RICH_SIGNATURE = 0x68636952  # "Rich" (little-endian)
DANS_SIGNATURE = 0x536E6144  # "DanS" (little-endian)

# DOS header offsets
DOS_NUM_RELOCS_OFFSET = 0x06  # Number of relocations
DOS_HEADER_PARA_OFFSET = 0x08  # Size of header in paragraphs
DOS_RELOC_OFFSET = 0x18  # File address of relocation table
DOS_PE_OFFSET = 0x3C  # File address of PE header

# PE header offsets (relative to PE signature)
PE_MACHINE_OFFSET = 4  # Machine type field

# Machine type mapping
# From https://msdn.microsoft.com/en-us/windows/hardware/gg463119.aspx
MACHINE_TYPES = {
    0x8664: "x64",
    0x14C: "x32",
    0x1D3: "Matsushita AM33",
    0x1C0: "ARM LE",
    0x1C4: "ARMv7+ Thumb",
    0xAA64: "ARMv8 64bit",
    0xEBC: "EFI bytecode",
    0x200: "Intel Itanium",
    0x9041: "Mitsubishi M32R LE",
    0x266: "MIPS16",
    0x366: "MIPS w/FPU",
    0x466: "MIPS16 w/FPU",
    0x1F0: "PowerPC LE",
    0x1F1: "PowerPC w/FPU",
    0x166: "MIPS LE",
    0x1A2: "Hitachi SH3",
    0x1A3: "Hitachi SH3 DSP",
    0x1A6: "Hitachi SH4",
    0x1A8: "Hitachi SH5",
    0x1C2: "ARM or Thumb",
    0x169: "MIPS LE WCE v2",
}


def get_machine_type(machine_id: int) -> str:
    """Get human-readable machine type name."""
    return MACHINE_TYPES.get(machine_id, "Unknown")
