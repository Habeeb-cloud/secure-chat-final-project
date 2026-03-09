"""
client.py
E2EE chat client (WhatsApp-style idea, simplified):
- registers username + ECDH public key
- /key <user> fetches and caches their public key
- derives and caches a persistent AES session key per user (ECDH + HKDF)
- encrypts payload for the recipient (server cannot decrypt)
- receiver decrypts locally before displaying
- CRC32 is used as "error control" demo on plaintext (verify after decrypt)
"""

import base64
import json
import socket
import threading

from client.key_exchange import generate_keypair, load_public_key, derive_shared_key
from client.encryption import encrypt_message, decrypt_message
from client.error_control import add_integrity, verify_integrity
from collections import defaultdict, deque
from datetime import datetime

HOST = "127.0.0.1"
PORT = 5000


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def receive_messages(
    sock: socket.socket,
    username: str,                 # ✅ added
    my_private_key,
    my_pubkey_pem: str,
    peer_pubkeys: dict[str, str],
    session_keys: dict[str, bytes],
) -> None:
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

            if mtype == "registered":
                print(f"\n[server] Registered as {msg.get('username')}")
                continue

            if mtype == "error":
                print(f"\n[server] ERROR: {msg.get('message')}")
                continue

            if mtype == "pubkey":
                u = msg.get("username")
                pk = msg.get("pubkey")
                if u and pk:
                    peer_pubkeys[u] = pk
                    print(f"\n[server] Saved public key for {u}.")
                    # derive session key immediately (persistent per user)
                    try:
                        peer_key = load_public_key(pk.encode("utf-8"))
                        session_keys[u] = derive_shared_key(my_private_key, peer_key)
                        print(f"[client] Session key derived for {u}.")
                    except Exception as e:
                        print(f"[client] Failed to derive key for {u}: {e}")
                continue

            if mtype == "chat":
                # ✅ STRICT RECIPIENT CHECK
                intended = msg.get("to", "")
                if intended != username:
                    # Ignore messages not meant for this client
                    continue

                sender = msg.get("from", "unknown")
                enc_payload_b64 = msg.get("payload", "")
                integrity = msg.get("integrity", "")
                sender_pubkey = msg.get("from_pubkey", "")

                # If we don't have sender session key yet, derive it using sender_pubkey
                if sender not in session_keys:
                    if sender_pubkey:
                        peer_pubkeys[sender] = sender_pubkey
                        try:
                            peer_key = load_public_key(sender_pubkey.encode("utf-8"))
                            session_keys[sender] = derive_shared_key(my_private_key, peer_key)
                            print(f"\n[client] Derived and cached session key for {sender}.")
                        except Exception as e:
                            print(f"\n[client] Cannot derive key for {sender}: {e}")
                            continue
                    else:
                        print(f"\n[client] No key for sender {sender}. Ask for it: /key {sender}")
                        continue

                # Decrypt
                try:
                    plaintext_bytes = decrypt_message(session_keys[sender], b64d(enc_payload_b64))
                    plaintext = plaintext_bytes.decode("utf-8", errors="replace")
                except Exception as e:
                    print(f"\n[client] Decryption failed from {sender}: {e}")
                    continue

                # CRC verification (error-control demo)
                if verify_integrity(plaintext, integrity):
                    print(f"\n[{sender}] {plaintext}")
                else:
                    print(f"\n[WARNING] CRC integrity failed for message from {sender}")
                continue

            print(f"\n[server] {msg}")

        except OSError:
            break


def main() -> None:
    username = input("Enter your username (unique): ").strip()
    if not username:
        print("Username required.")
        return

    # ECDH identity keypair for this run (persistent session keys derived from this)
    kp = generate_keypair()
    my_pubkey_pem = kp.public_key.public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.PEM,
        format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    peer_pubkeys: dict[str, str] = {}
    session_keys: dict[str, bytes] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    # Register
    sock.sendall(json.dumps({
        "type": "register",
        "username": username,
        "pubkey": my_pubkey_pem,
    }).encode("utf-8"))

    print(f"Connected to server {HOST}:{PORT}")
    print("Commands:")
    print("  /key <username>          fetch and cache user's public key + derive session key")
    print("  /msg <username> <text>   send an encrypted message (E2EE)")
    print("  quit                     exit\n")

    threading.Thread(
        target=receive_messages,
        args=(sock, username, kp.private_key, my_pubkey_pem, peer_pubkeys, session_keys),  # ✅ updated
        daemon=True
    ).start()

    try:
        while True:
            line = input().strip()
            if not line:
                continue
            if line.lower() == "quit":
                break

            if line.startswith("/key "):
                target = line[5:].strip()
                sock.sendall(json.dumps({"type": "get_pubkey", "username": target}).encode("utf-8"))
                continue

            if line.startswith("/msg "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Usage: /msg <username> <text>")
                    continue

                to_user = parts[1].strip()
                msg_text = parts[2]

                # Require cached session key (persistent approach)
                if to_user not in session_keys:
                    print(f"No session key for {to_user}. Run: /key {to_user}")
                    continue

                # CRC over plaintext (error-control demo)
                integrity = add_integrity(msg_text)

                # Encrypt plaintext for recipient using derived session key
                blob = encrypt_message(session_keys[to_user], msg_text.encode("utf-8"))
                payload_b64 = b64e(blob)

                sock.sendall(json.dumps({
                    "type": "chat",
                    "to": to_user,
                    "payload": payload_b64,
                    "integrity": integrity,
                    "from_pubkey": my_pubkey_pem,  # lets receiver derive key if needed
                }).encode("utf-8"))
                continue

            print("Unknown command. Use /key, /msg, or quit.")

    finally:
        sock.close()
        print("Disconnected.")


if __name__ == "__main__":
    main()
