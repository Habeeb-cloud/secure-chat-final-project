"""
key_exchange.py
Session key establishment (DH/ECDH will be implemented later).
"""

class KeyExchangeError(Exception):
    pass

def establish_session_key() -> bytes:
    """Create/derive a shared session key."""
    raise NotImplementedError
