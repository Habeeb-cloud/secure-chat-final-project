"""
encryption.py
AES-GCM encryption/decryption using the cryptography library.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionError(Exception):
    pass


def generate_key() -> bytes:
    """Generate a 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt using AES-GCM.
    Returns: nonce (12 bytes) + ciphertext+tag (variable)
    """
    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return nonce + ciphertext
    except Exception as e:
        raise EncryptionError(str(e)) from e


def decrypt_message(key: bytes, blob: bytes) -> bytes:
    """
    Decrypt AES-GCM blob: nonce (12 bytes) + ciphertext+tag.
    """
    try:
        if len(blob) < 13:
            raise EncryptionError("Ciphertext blob too short.")
        nonce = blob[:12]
        ciphertext = blob[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        raise EncryptionError(str(e)) from e
