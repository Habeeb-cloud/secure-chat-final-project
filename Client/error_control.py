"""
error_control.py
Error detection/correction utilities (CRC/Hamming will be implemented later).
"""

class ErrorControlError(Exception):
    pass

def add_integrity(data: bytes) -> bytes:
    """Attach integrity or redundancy information to data."""
    raise NotImplementedError

def verify_and_strip(data: bytes) -> bytes:
    """Verify data integrity/correct errors and return original payload."""
    raise NotImplementedError
