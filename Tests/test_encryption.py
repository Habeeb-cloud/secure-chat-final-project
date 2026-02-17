from client.encryption import generate_key, encrypt_message, decrypt_message


def test_aes_gcm_roundtrip():
    key = generate_key()
    plaintext = b"hello secure chat"
    blob = encrypt_message(key, plaintext)
    recovered = decrypt_message(key, blob)
    assert recovered == plaintext
