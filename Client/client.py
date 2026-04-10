"""
client.py
Secure E2EE chat client.

Features
- registers username + ECDH public key
- requests another user's public key
- shows public key fingerprint for verification
- requires explicit trust before deriving session key
- derives AES session key using ECDH + HKDF
- encrypts messages using AES-256-GCM
- CRC32 used to verify integrity
"""
print("THIS IS THE NEW CLIENT FILE")
import base64
import json
import socket
import threading

from client.key_exchange import (
    generate_keypair,
    load_public_key,
    derive_shared_key,
    public_key_fingerprint,
)

from client.encryption import encrypt_message, decrypt_message
from client.error_control import add_integrity, verify_integrity

HOST = "127.0.0.1"
PORT = 5000


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def receive_messages(
    sock,
    username,
    my_private_key,
    my_pubkey_pem,
    peer_pubkeys,
    pending_pubkeys,
    session_keys,
):
    while True:
        try:
            data = sock.recv(4096)

            if not data:
                break

            text = data.decode("utf-8", errors="replace")

            try:
                msg = json.loads(text)
            except json.JSONDecodeError:
                print("\n[RAW]:", text)
                continue

            mtype = msg.get("type", "unknown")

            # REGISTERED
            if mtype == "registered":
                print(f"\n[server] Registered as {msg.get('username')}")
                continue

            # ERROR
            if mtype == "error":
                print(f"\n[server] ERROR: {msg.get('message')}")
                continue

            # PUBLIC KEY RECEIVED
            if mtype == "pubkey":
                u = msg.get("username")
                pk = msg.get("pubkey")

                if u and pk:
                    print(f"\n[server] Public key received for {u}")

                    fingerprint = public_key_fingerprint(pk.encode())

                    print(f"[security] Fingerprint for {u}:")
                    print(f"{fingerprint}")

                    print(f"[security] Run /trust {u} to accept this key")
                    print(f"[security] Or /reject {u} to reject it")

                    # store as pending until user explicitly trusts it
                    pending_pubkeys[u] = pk

                continue

            # CHAT MESSAGE
            if mtype == "chat":
                intended = msg.get("to", "")

                if intended != username:
                    continue

                sender = msg.get("from", "unknown")
                enc_payload_b64 = msg.get("payload", "")
                integrity = msg.get("integrity", "")
                sender_pubkey = msg.get("from_pubkey", "")

                # derive session key if needed
                if sender not in session_keys:
                    if sender_pubkey:
                        try:
                            peer_key = load_public_key(sender_pubkey.encode())
                            session_keys[sender] = derive_shared_key(
                                my_private_key,
                                peer_key
                            )
                            print(f"\n[client] Derived session key for {sender}")
                        except Exception as e:
                            print(f"\n[client] Cannot derive key: {e}")
                            continue
                    else:
                        print(f"\n[client] Missing key for {sender}. Run /key {sender}")
                        continue

                # DECRYPT MESSAGE
                try:
                    plaintext_bytes = decrypt_message(
                        session_keys[sender],
                        b64d(enc_payload_b64)
                    )

                    plaintext = plaintext_bytes.decode("utf-8", errors="replace")

                except Exception as e:
                    print(f"\n[client] Decryption failed: {e}")
                    continue

                # CRC VERIFY
                if verify_integrity(plaintext, integrity):
                    print(f"\n[{sender}] {plaintext}")
                else:
                    print(f"\n[WARNING] CRC verification failed")

                continue

        except OSError:
            break


def main():
    username = input("Enter your username: ").strip()

    if not username:
        print("Username required")
        return

    kp = generate_keypair()

    from cryptography.hazmat.primitives import serialization

    my_pubkey_pem = kp.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    peer_pubkeys = {}
    pending_pubkeys = {}
    session_keys = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    # REGISTER
    sock.sendall(json.dumps({
        "type": "register",
        "username": username,
        "pubkey": my_pubkey_pem
    }).encode())

    print(f"Connected to server {HOST}:{PORT}")

    print("\nCommands:")
    print("/key <user>            fetch public key")
    print("/trust <user>          trust pending public key")
    print("/reject <user>         reject pending public key")
    print("/msg <user> <text>     send encrypted message")
    print("quit\n")

    threading.Thread(
        target=receive_messages,
        args=(
            sock,
            username,
            kp.private_key,
            my_pubkey_pem,
            peer_pubkeys,
            pending_pubkeys,
            session_keys,
        ),
        daemon=True
    ).start()

    try:
        while True:
            line = input().strip()

            if not line:
                continue

            if line.lower() == "quit":
                break

            # KEY REQUEST
            if line.startswith("/key "):
                target = line[5:].strip()

                sock.sendall(json.dumps({
                    "type": "get_pubkey",
                    "username": target
                }).encode())

                continue

            # TRUST PENDING KEY
            if line.startswith("/trust "):
                target = line[7:].strip()

                if target not in pending_pubkeys:
                    print(f"No pending key for {target}")
                    continue

                pk = pending_pubkeys.pop(target)
                peer_pubkeys[target] = pk

                try:
                    peer_key = load_public_key(pk.encode())
                    session_keys[target] = derive_shared_key(
                        kp.private_key,
                        peer_key
                    )
                    print(f"[client] Secure session key established for {target}")
                except Exception as e:
                    print(f"[client] Failed to derive key for {target}: {e}")

                continue

            # REJECT PENDING KEY
            if line.startswith("/reject "):
                target = line[8:].strip()

                if target in pending_pubkeys:
                    pending_pubkeys.pop(target, None)
                    print(f"[client] Rejected key for {target}")
                else:
                    print(f"No pending key for {target}")

                continue

            # SEND MESSAGE
            if line.startswith("/msg "):
                parts = line.split(" ", 2)

                if len(parts) < 3:
                    print("Usage: /msg <user> <text>")
                    continue

                to_user = parts[1]
                message = parts[2]

                if to_user not in session_keys:
                    print(f"No trusted key for {to_user}. Run /key {to_user} then /trust {to_user}")
                    continue

                integrity = add_integrity(message)

                encrypted_blob = encrypt_message(
                    session_keys[to_user],
                    message.encode()
                )

                payload_b64 = b64e(encrypted_blob)

                sock.sendall(json.dumps({
                    "type": "chat",
                    "to": to_user,
                    "payload": payload_b64,
                    "integrity": integrity,
                    "from_pubkey": my_pubkey_pem
                }).encode())

                continue

            print("Unknown command")

    finally:
        sock.close()
        print("Disconnected")


if __name__ == "__main__":
    main()