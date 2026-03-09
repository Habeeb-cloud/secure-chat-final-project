"""
server.py
Directory + router server (E2EE-friendly):
- clients register username + public key
- clients can request another user's public key
- server forwards chat messages WITHOUT decrypting
"""

import json
import socket
import threading

HOST = "127.0.0.1"
PORT = 5000

clients: list[socket.socket] = []
user_sockets: dict[str, socket.socket] = {}
user_pubkeys: dict[str, str] = {}


def safe_send(sock: socket.socket, obj: dict) -> None:
    try:
        sock.sendall(json.dumps(obj).encode("utf-8"))
    except OSError:
        pass


def handle_client(client_socket: socket.socket) -> None:
    print("New client connected.")
    clients.append(client_socket)

    username: str | None = None

    try:
        # ---- REGISTER first ----
        first = client_socket.recv(4096)
        if not first:
            return

        try:
            reg = json.loads(first.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            safe_send(client_socket, {"type": "error", "message": "invalid JSON on register"})
            return

        if reg.get("type") != "register":
            safe_send(client_socket, {"type": "error", "message": "must register first"})
            return

        username = (reg.get("username") or "").strip()
        pubkey = reg.get("pubkey") or ""

        if not username or not pubkey:
            safe_send(client_socket, {"type": "error", "message": "username/pubkey missing"})
            return

        if username in user_sockets:
            safe_send(client_socket, {"type": "error", "message": "username already taken"})
            return

        user_sockets[username] = client_socket
        user_pubkeys[username] = pubkey

        print(f"Registered user: {username}")
        safe_send(client_socket, {"type": "registered", "username": username})

        # ---- Main loop ----
        while True:
            raw = client_socket.recv(4096)
            if not raw:
                break

            try:
                msg = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                safe_send(client_socket, {"type": "error", "message": "invalid JSON"})
                continue

            mtype = msg.get("type", "")

            # 1) Public key lookup
            if mtype == "get_pubkey":
                target = (msg.get("username") or "").strip()
                if target in user_pubkeys:
                    safe_send(client_socket, {
                        "type": "pubkey",
                        "username": target,
                        "pubkey": user_pubkeys[target],
                    })
                else:
                    safe_send(client_socket, {"type": "error", "message": f"no such user {target}"})
                continue

            # 2) Forward encrypted chat (server cannot decrypt)
            if mtype == "chat":
                to_user = (msg.get("to") or "").strip()
                if not to_user or to_user not in user_sockets:
                    safe_send(client_socket, {"type": "error", "message": f"user '{to_user}' not online"})
                    continue

                # Force sender identity to the registered username (prevents spoofing)
                msg["from"] = username
                msg["to"] = to_user
                msg["type"] = "chat"

                # Optional proof in server console: payload should look like base64 ciphertext
                payload_preview = str(msg.get("payload", ""))[:30]
                print(f"Forwarding chat {username} -> {to_user} | payload preview: {payload_preview}...")

                safe_send(user_sockets[to_user], msg)
                continue

            safe_send(client_socket, {"type": "error", "message": "unknown message type"})

    except (ConnectionResetError, OSError):
        pass
    finally:
        print("Client disconnected.")
        if client_socket in clients:
            clients.remove(client_socket)

        if username and user_sockets.get(username) is client_socket:
            user_sockets.pop(username, None)
            user_pubkeys.pop(username, None)

        try:
            client_socket.close()
        except OSError:
            pass


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    server.settimeout(1.0)

    running = True
    print(f"Server running on {HOST}:{PORT}")
    print("Type 'quit' then press Enter to stop the server.")

    def console_listener() -> None:
        nonlocal running
        while running:
            try:
                cmd = input()
            except EOFError:
                break
            if cmd.strip().lower() == "quit":
                running = False

    threading.Thread(target=console_listener, daemon=True).start()

    try:
        while running:
            try:
                client_socket, _ = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()

    finally:
        print("Server shutting down.")
        for s in list(user_sockets.values()):
            try:
                s.close()
            except OSError:
                pass
        user_sockets.clear()
        user_pubkeys.clear()
        server.close()


if __name__ == "__main__":
    main()
