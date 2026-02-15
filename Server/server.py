"""
server.py
Basic chat server with clean shutdown via 'quit'.
"""

import socket
import threading

HOST = "127.0.0.1"
PORT = 5000

clients: list[socket.socket] = []


def handle_client(client_socket: socket.socket) -> None:
    print("New client connected.")
    clients.append(client_socket)

    try:
        while True:
            message = client_socket.recv(1024)
            if not message:
                break

            for client in clients:
                if client != client_socket:
                    client.send(message)

    except (ConnectionResetError, OSError):
        pass
    finally:
        print("Client disconnected.")
        if client_socket in clients:
            clients.remove(client_socket)
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
                client_socket, addr = server.accept()
            except socket.timeout:
                continue

            threading.Thread(
                target=handle_client,
                args=(client_socket,),
                daemon=True
            ).start()

    finally:
        print("Server shutting down.")
        for c in clients:
            try:
                c.close()
            except OSError:
                pass
        server.close()


if __name__ == "__main__":
    main()
