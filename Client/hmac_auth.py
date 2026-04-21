import hmac
import hashlib

def generate_hmac(key: bytes, message: bytes) -> str:
    mac = hmac.new(key, message, hashlib.sha256).digest()
    return mac.hex()

def verify_hmac(key: bytes, message: bytes, mac_hex: str) -> bool:
    expected = hmac.new(key, message, hashlib.sha256).digest()
    return hmac.compare_digest(expected, bytes.fromhex(mac_hex))