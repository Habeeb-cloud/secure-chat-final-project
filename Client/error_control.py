"""
error_control.py
Integrity checking using CRC32.
"""

import zlib


def crc32_hex(data: bytes) -> str:
    """Return CRC32 as 8-char hex string."""
    return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")


def add_integrity(payload: str) -> str:
    """
    Compute CRC32 for a payload string.
    Returns hex digest string.
    """
    return crc32_hex(payload.encode("utf-8"))


def verify_integrity(payload: str, integrity: str) -> bool:
    """Verify payload matches the given CRC32 hex."""
    expected = add_integrity(payload)
    return expected == integrity
