"""
key_exchange.py
ECDH key exchange + HKDF key derivation to produce an AES-256 key.
Includes public key fingerprinting for verification.
"""

from __future__ import annotations
from dataclasses import dataclass
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


@dataclass
class ECDHKeyPair:
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey


def generate_keypair() -> ECDHKeyPair:
    """Generate an ECDH keypair using NIST P-256."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return ECDHKeyPair(private_key=private_key, public_key=private_key.public_key())


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize public key to bytes for sending."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """Load peer public key."""
    key = serialization.load_pem_public_key(data)
    return key  # type: ignore


def derive_shared_key(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
    *,
    salt: bytes | None = None,
    info: bytes = b"secure-chat-ecdh",
) -> bytes:
    """
    Perform ECDH and derive AES-256 key using HKDF.
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )

    return hkdf.derive(shared_secret)


def public_key_fingerprint(pubkey_pem: bytes) -> str:
    """
    Generate SHA256 fingerprint of public key.
    Used to verify authenticity and prevent MITM attacks.
    """
    digest = hashlib.sha256(pubkey_pem).hexdigest()
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2))