"""
server.py
Directory + router server for E2EE chat.

Handles:
- user registration
- public key lookup
- message forwarding (payload + hmac)
- proper TCP framing (FIXED)
"""

import json
import socket
import threading

HOST = "127.0.0.1"
PORT = 5001

user_sockets = {}
user_pubkeys = {}


# 🔥 FIX: newline-delimited JSON
def safe_send(sock, obj):
    try:
        sock.sendall((json.dumps(obj) + "\n").encode())
    except Exception as e:
        print(f"[send error] {e}")


def handle_client(client_socket):
    username = None
    buffer = ""

    try:
        while True:
            chunk = client_socket.recv(4096).decode()
            if not chunk:
                break

            buffer += chunk

            # 🔥 FIX: handle multiple / partial messages
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)

                try:
                    msg = json.loads(line)
                except:
                    print("[error] bad json")
                    continue

                mtype = msg.get("type")

                # ===== REGISTER =====
                if mtype == "register":
                    username = msg.get("username")
                    pubkey = msg.get("pubkey")

                    if not username:
                        continue

                    user_sockets[username] = client_socket

                    if pubkey:
                        user_pubkeys[username] = pubkey

                    print(f"[+] {username} connected")

                    safe_send(client_socket, {
                        "type": "registered",
                        "username": username
                    })

                # ===== GET PUBLIC KEY =====
                elif mtype == "get_pubkey":
                    target = msg.get("username")

                    if target in user_pubkeys:
                        safe_send(client_socket, {
                            "type": "pubkey",
                            "username": target,
                            "pubkey": user_pubkeys[target]
                        })
                    else:
                        safe_send(client_socket, {
                            "type": "error",
                            "message": "user not found"
                        })

                # ===== CHAT =====
                elif mtype == "chat":
                    to_user = msg.get("to")

                    if to_user in user_sockets:
                        forward = {
                            "type": "chat",
                            "from": username,
                            "payload": msg.get("payload"),
                            "hmac": msg.get("hmac")  # ✅ REQUIRED
                        }

                        safe_send(user_sockets[to_user], forward)

                        print(f"[msg] {username} -> {to_user}")
                    else:
                        print(f"[warn] {to_user} not online")

    except Exception as e:
        print(f"[connection error] {e}")

    finally:
        if username:
            user_sockets.pop(username, None)
            user_pubkeys.pop(username, None)
            print(f"[-] {username} disconnected")

        client_socket.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 🔥 Prevent port lock issue
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen()

    print(f"Server running on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"[new connection] {addr}")

        threading.Thread(
            target=handle_client,
            args=(client_socket,),
            daemon=True
        ).start()


if __name__ == "__main__":
    main()