"""
server.py
Directory + router server for E2EE chat.
"""

import json
import socket
import threading

HOST = "127.0.0.1"
PORT = 5000

user_sockets = {}
user_pubkeys = {}


def safe_send(sock, obj):
    try:
        sock.sendall(json.dumps(obj).encode())
    except:
        pass


def handle_client(client_socket):
    username = None

    try:
        data = client_socket.recv(4096)
        reg = json.loads(data.decode())

        if reg.get("type") != "register":
            return

        username = reg["username"]
        pubkey = reg["pubkey"]

        user_sockets[username] = client_socket
        user_pubkeys[username] = pubkey

        print(f"User registered: {username}")

        safe_send(client_socket, {"type": "registered", "username": username})

        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            msg = json.loads(data.decode())
            mtype = msg.get("type")

            if mtype == "get_pubkey":
                target = msg["username"]

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

            elif mtype == "chat":
                to_user = msg["to"]

                if to_user in user_sockets:
                    msg["from"] = username
                    safe_send(user_sockets[to_user], msg)

                    preview = msg["payload"][:30]
                    print(f"{username} -> {to_user} | ciphertext: {preview}...")

    finally:
        if username in user_sockets:
            del user_sockets[username]
            del user_pubkeys[username]

        client_socket.close()
        print("Client disconnected")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"Server running on {HOST}:{PORT}")

    while True:
        client_socket, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()


if __name__ == "__main__":
    main()