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
    Returns nonce + ciphertext.
    """
    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    except Exception as e:
        raise EncryptionError(str(e))


def decrypt_message(key: bytes, blob: bytes) -> bytes:
    """
    Decrypt AES-GCM message.
    """
    try:
        nonce = blob[:12]
        ciphertext = blob[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise EncryptionError(str(e))