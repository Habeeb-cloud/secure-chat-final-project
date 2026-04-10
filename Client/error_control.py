"""
error_control.py
Integrity checking using CRC32.
"""

import zlib


def crc32_hex(data: bytes) -> str:
    return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")


def add_integrity(payload: str) -> str:
    return crc32_hex(payload.encode("utf-8"))


def verify_integrity(payload: str, integrity: str) -> bool:
    expected = add_integrity(payload)
    return expected == integrity