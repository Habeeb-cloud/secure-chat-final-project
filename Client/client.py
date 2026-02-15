"""
client.py
Minimal chat client (connect, send, receive).
"""

import socket
import threading

HOST = "127.0.0.1"
PORT = 5000


def receive_messages(sock: socket.socket) -> None:
    """Listen for incoming messages from the server and print them."""
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            print("\n[Message received]:", data.decode("utf-8", errors="replace"))
        except OSError:
            break


def main() -> None:
    username = input("Enter your name: ").strip() or "Anonymous"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"Connected to server {HOST}:{PORT}")
    print("Type messages and press Enter to send. Type 'quit' to exit.\n")

    # Start background receiver thread
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    try:
        while True:
            msg = input()
            if msg.strip().lower() == "quit":
                break

            outgoing = f"{username}: {msg}"
            sock.send(outgoing.encode("utf-8"))

    finally:
        sock.close()
        print("Disconnected.")


if __name__ == "__main__":
    main()
