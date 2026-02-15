"""
encryption.py
Encryption/decryption utilities (AES will be implemented later).
"""

class EncryptionError(Exception):
    pass

def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext using a symmetric key."""
    raise NotImplementedError

def decrypt_message(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using a symmetric key."""
    raise NotImplementedError
