"""
client.py
Chat client (connect, send, receive) using JSON messages + CRC32 integrity.
"""

import socket
import threading

from client.message_format import build_message, parse_message
from client.error_control import add_integrity, verify_integrity

HOST = "127.0.0.1"
PORT = 5000


def receive_messages(sock: socket.socket) -> None:
    """Listen for incoming messages from the server and print them."""
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break

            text = data.decode("utf-8", errors="replace")

            try:
                parsed = parse_message(text)

                sender = parsed.get("sender", "Unknown")
                payload = parsed.get("payload", "")
                integrity = parsed.get("integrity", "")

                if verify_integrity(payload, integrity):
                    print(f"\n[{sender}]: {payload}")
                else:
                    print(f"\n[WARNING] Integrity check failed for message from {sender}")

            except Exception:
                # Fallback if message isn't valid JSON
                print("\n[Message received]:", text)

        except OSError:
            break


def main() -> None:
    username = input("Enter your name: ").strip() or "Anonymous"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"Connected to server {HOST}:{PORT}")
    print("Type messages and press Enter to send. Type 'quit' to exit.\n")

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    try:
        while True:
            msg = input()
            if msg.strip().lower() == "quit":
                break

            integrity = add_integrity(msg)
            outgoing_json = build_message(username, msg, integrity)
            sock.send(outgoing_json.encode("utf-8"))

    finally:
        sock.close()
        print("Disconnected.")


if __name__ == "__main__":
    main()
