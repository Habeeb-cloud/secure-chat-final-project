import hmac
import hashlib

def generate_hmac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def verify_hmac(key: bytes, message: bytes, tag: str) -> bool:
    expected = generate_hmac(key, message)
    return hmac.compare_digest(expected, tag)