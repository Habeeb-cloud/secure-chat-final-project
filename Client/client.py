"""
client.py
Secure E2EE chat client with message storage.
"""

import base64
import json
import socket
import threading

from database import (
    get_user,
    get_contacts,
    add_contact,
    save_message,
    get_messages
)

from cryptography.hazmat.primitives import serialization

from key_exchange import (
    load_public_key,
    derive_shared_key,
    public_key_fingerprint,
)

from encryption import encrypt_message, decrypt_message
from error_control import add_integrity, verify_integrity
from hmac_auth import generate_hmac, verify_hmac

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

            msg = json.loads(data.decode())
            mtype = msg.get("type")

            # 🔐 HANDLE PUBLIC KEY RESPONSE
            if mtype == "pubkey":
                u = msg.get("username")
                pk = msg.get("pubkey")

                if u and pk:
                    print(f"\n[server] Public key received for {u}")

                    fingerprint = public_key_fingerprint(pk.encode())

                    print(f"[security] Fingerprint for {u}:")
                    print(f"{fingerprint}")
                    print(f"[security] Run /trust {u} to accept this key")

                    pending_pubkeys[u] = pk

                continue

            # 💬 CHAT HANDLING
            if mtype == "chat":
                if msg.get("to") != username:
                    continue

                sender = msg.get("from")
                enc_payload_b64 = msg.get("payload")
                integrity = msg.get("integrity")
                hmac_tag = msg.get("hmac")
                sender_pubkey = msg.get("from_pubkey")

                if sender not in session_keys:
                    peer_key = load_public_key(sender_pubkey.encode())
                    session_keys[sender] = derive_shared_key(
                        my_private_key,
                        peer_key
                    )

                plaintext_bytes = decrypt_message(
                    session_keys[sender],
                    b64d(enc_payload_b64)
                )
                plaintext = plaintext_bytes.decode()

                if verify_integrity(plaintext, integrity) and verify_hmac(
                    session_keys[sender],
                    plaintext_bytes,
                    hmac_tag
                ):
                    print(f"\n[{sender}] {plaintext}")

                    # 🔥 SAVE RECEIVED MESSAGE
                    save_message(sender, username, enc_payload_b64)

                else:
                    print("\n[WARNING] Message failed verification")

        except Exception as e:
            print(f"\n[error] {e}")
            break


def main():
    username = input("Enter your username: ").strip()

    user_data = get_user(username)

    if not user_data:
        print("User not found in database.")
        return

    _, _, public_key_pem, private_key_pem = user_data

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )

    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )

    class KeyPair:
        def __init__(self, private_key, public_key):
            self.private_key = private_key
            self.public_key = public_key

    kp = KeyPair(private_key, public_key)
    my_pubkey_pem = public_key_pem

    peer_pubkeys = {}
    pending_pubkeys = {}
    session_keys = {}

    # 🔥 LOAD SAVED CONTACTS
    saved_contacts = get_contacts(username)

    for contact_name, pubkey in saved_contacts:
        if pubkey:
            peer_pubkeys[contact_name] = pubkey

            try:
                peer_key = load_public_key(pubkey.encode())
                session_keys[contact_name] = derive_shared_key(
                    kp.private_key,
                    peer_key
                )
                print(f"[auto] Trusted contact loaded: {contact_name}")
            except:
                pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    sock.sendall(json.dumps({
        "type": "register",
        "username": username,
        "pubkey": my_pubkey_pem
    }).encode())

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

    print("Connected. Commands: /key /trust /msg /history")

    while True:
        line = input().strip()

        if line.startswith("/key "):
            target = line[5:].strip()
            sock.sendall(json.dumps({
                "type": "get_pubkey",
                "username": target
            }).encode())

        elif line.startswith("/trust "):
            target = line[7:].strip()

            if target not in pending_pubkeys:
                print("No pending key")
                continue

            pk = pending_pubkeys.pop(target)
            peer_pubkeys[target] = pk

            add_contact(username, target, pk)

            peer_key = load_public_key(pk.encode())
            session_keys[target] = derive_shared_key(
                kp.private_key,
                peer_key
            )

            print(f"[trusted] {target}")

        elif line.startswith("/msg "):
            parts = line.split(" ", 2)

            if len(parts) < 3:
                continue

            to_user = parts[1]
            message = parts[2]

            if to_user not in session_keys:
                print("Trust user first")
                continue

            integrity = add_integrity(message)
            hmac_tag = generate_hmac(
                session_keys[to_user],
                message.encode()
            )

            encrypted_blob = encrypt_message(
                session_keys[to_user],
                message.encode()
            )

            payload_b64 = b64e(encrypted_blob)

            # 🔥 SAVE SENT MESSAGE
            save_message(username, to_user, payload_b64)

            sock.sendall(json.dumps({
                "type": "chat",
                "to": to_user,
                "payload": payload_b64,
                "integrity": integrity,
                "hmac": hmac_tag,
                "from_pubkey": my_pubkey_pem
            }).encode())

        elif line.startswith("/history "):
            target = line[9:].strip()

            chats = get_messages(username, target)

            print(f"\n--- Chat with {target} ---")
            for sender, msg, time in chats:

                # 🔥 DECRYPT HISTORY (NEW)
                if sender == username:
                    key = session_keys.get(target)
                else:
                    key = session_keys.get(sender)

                try:
                    if key:
                        decrypted = decrypt_message(key, b64d(msg)).decode()
                    else:
                        decrypted = "[no key]"
                except:
                    decrypted = "[decryption failed]"

                print(f"[{time}] {sender}: {decrypted}")

            print("-------------------------")

        elif line == "quit":
            break


if __name__ == "__main__":
    main()