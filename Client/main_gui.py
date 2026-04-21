import tkinter as tk
from tkinter import messagebox
import base64
import socket
import json
import threading

from hmac_auth import generate_hmac, verify_hmac

from database import (
    create_user,
    login_user,
    get_contacts,
    get_messages,
    save_message,
    add_contact,
    create_tables,
    get_user,
    delete_contact,
    delete_messages
)

from encryption import encrypt_message, decrypt_message

from key_exchange import (
    load_public_key,
    derive_shared_key
)

from cryptography.hazmat.primitives import serialization


class App:
    def __init__(self, root):
        create_tables()

        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("400x450")

        self.current_frame = None

        self.session_keys = {}
        self.private_key = None

        self.active_chat = None
        self.chat_widget = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(("127.0.0.1", 5001))

        self.username = None

        self.show_signup()

    def send_json(self, obj):
        self.sock.sendall((json.dumps(obj) + "\n").encode())

    def switch_frame(self, new_frame):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = new_frame
        self.current_frame.pack(fill="both", expand=True)

    def ensure_key(self, contact):
        if contact in self.session_keys:
            return self.session_keys[contact]

        contacts = get_contacts(self.username)
        for name, pubkey in contacts:
            if name == contact and pubkey:
                peer_key = load_public_key(pubkey.encode())

                shared_info = f"{min(self.username, contact)}:{max(self.username, contact)}".encode()

                self.session_keys[contact] = derive_shared_key(
                    self.private_key,
                    peer_key,
                    info=shared_info
                )
                return self.session_keys[contact]

        return None

    # ================= RECEIVER =================
    def start_receiver(self):
        def receive():
            buffer = ""

            while True:
                try:
                    chunk = self.sock.recv(4096).decode()
                    if not chunk:
                        break

                    buffer += chunk

                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)

                        try:
                            msg = json.loads(line)
                        except:
                            continue

                        if msg.get("type") == "pubkey":
                            user = msg["username"]
                            pk = msg["pubkey"]

                            peer_key = load_public_key(pk.encode())

                            shared_info = f"{min(self.username, user)}:{max(self.username, user)}".encode()

                            self.session_keys[user] = derive_shared_key(
                                self.private_key,
                                peer_key,
                                info=shared_info
                            )

                            add_contact(self.username, user, pk)

                            self.root.after(0, lambda:
                                messagebox.showinfo("Success", f"{user} added")
                            )
                            continue

                        if msg.get("type") == "chat":
                            sender = msg.get("from")

                            # 🔥 FIX DUPLICATE
                            if sender == self.username:
                                continue

                            payload = msg.get("payload")
                            hmac_tag = msg.get("hmac")

                            key = self.ensure_key(sender)
                            if not key:
                                continue

                            try:
                                decrypted_bytes = decrypt_message(
                                    key,
                                    base64.b64decode(payload.encode())
                                )

                                if not verify_hmac(key, decrypted_bytes, hmac_tag):
                                    continue

                            except:
                                continue

                            save_message(sender, self.username, payload)

                            self.root.after(
                                0,
                                self.display_message,
                                sender,
                                payload
                            )

                except Exception as e:
                    print("Receiver error:", e)
                    break

        threading.Thread(target=receive, daemon=True).start()

    def display_message(self, sender, payload):
        if not self.chat_widget or sender != self.active_chat:
            return

        key = self.ensure_key(sender)
        if not key:
            return

        try:
            decrypted = decrypt_message(
                key,
                base64.b64decode(payload.encode())
            ).decode()
        except:
            decrypted = "[decryption failed]"

        self.chat_widget.config(state="normal")
        self.chat_widget.insert("end", f"{sender}: {decrypted}\n")
        self.chat_widget.config(state="disabled")
        self.chat_widget.see("end")

    # ================= SIGNUP (RESTORED) =================
    def show_signup(self):
        frame = tk.Frame(self.root)

        tk.Button(frame, text="Go to Login",
                  command=self.show_login).pack(anchor="ne", padx=10, pady=10)

        form = tk.Frame(frame)
        form.pack(pady=20)

        tk.Label(form, text="Username").grid(row=0, column=0)
        username_entry = tk.Entry(form)
        username_entry.grid(row=0, column=1)

        tk.Label(form, text="Password").grid(row=1, column=0)
        password_entry = tk.Entry(form, show="*")
        password_entry.grid(row=1, column=1)

        tk.Label(form, text="Confirm Password").grid(row=2, column=0)
        confirm_entry = tk.Entry(form, show="*")
        confirm_entry.grid(row=2, column=1)

        def signup_action():
            u = username_entry.get()
            p = password_entry.get()
            c = confirm_entry.get()

            if not u or not p:
                messagebox.showerror("Error", "All fields required")
                return

            if p != c:
                messagebox.showerror("Error", "Passwords do not match")
                return

            if create_user(u, p):
                messagebox.showinfo("Success", "Account created")
                self.show_login()
            else:
                messagebox.showerror("Error", "Username exists")

        tk.Button(frame, text="Sign Up", command=signup_action).pack(pady=10)

        self.switch_frame(frame)

    # ================= LOGIN =================
    def show_login(self):
        frame = tk.Frame(self.root)

        tk.Button(frame, text="Back",
                  command=self.show_signup).pack(anchor="ne", padx=10, pady=10)

        form = tk.Frame(frame)
        form.pack(pady=30)

        tk.Label(form, text="Username").grid(row=0, column=0)
        username_entry = tk.Entry(form)
        username_entry.grid(row=0, column=1)

        tk.Label(form, text="Password").grid(row=1, column=0)
        password_entry = tk.Entry(form, show="*")
        password_entry.grid(row=1, column=1)

        def login_action():
            u = username_entry.get()
            p = password_entry.get()

            if not u or not p:
                messagebox.showerror("Error", "All fields required")
                return

            if login_user(u, p):
                self.username = u

                user = get_user(u)
                _, _, pub, priv = user

                self.private_key = serialization.load_pem_private_key(
                    priv.encode(),
                    password=None
                )

                self.send_json({
                    "type": "register",
                    "username": u,
                    "pubkey": pub
                })

                self.start_receiver()
                self.show_contacts(u)
            else:
                messagebox.showerror("Error", "Invalid credentials")

        tk.Button(frame, text="Login", command=login_action).pack()

        self.switch_frame(frame)

    # ================= CONTACTS =================
    def show_contacts(self, username):
        frame = tk.Frame(self.root)

        tk.Button(frame, text="+",
                  command=lambda: self.show_add_contact(username)).pack()

        contacts_list = tk.Listbox(frame)
        contacts_list.pack(fill="both", expand=True)

        for name, _ in get_contacts(username):
            contacts_list.insert(tk.END, name)

        def open_chat(event):
            sel = contacts_list.curselection()
            if sel:
                self.show_chat_page(username, contacts_list.get(sel[0]))

        contacts_list.bind("<<ListboxSelect>>", open_chat)

        self.switch_frame(frame)

    # ================= ADD =================
    def show_add_contact(self, username):
        frame = tk.Frame(self.root)

        entry = tk.Entry(frame)
        entry.pack()

        def add_action():
            name = entry.get().strip()
            if not name:
                return

            self.send_json({
                "type": "get_pubkey",
                "username": name
            })

        tk.Button(frame, text="Add", command=add_action).pack()

        self.switch_frame(frame)

    # ================= CHAT =================
    def show_chat_page(self, username, contact):
        frame = tk.Frame(self.root)

        top = tk.Frame(frame)
        top.pack(fill="x")

        tk.Button(top, text="Back",
                  command=lambda: self.show_contacts(username)).pack(side="left")

        tk.Label(top, text=contact).pack(side="left")

        def open_menu():
            menu = tk.Menu(self.root, tearoff=0)

            menu.add_command(label="Delete Contact",
                             command=lambda: [delete_contact(self.username, contact),
                                              self.show_contacts(self.username)])

            menu.add_command(label="Clear Chat",
                             command=lambda: [delete_messages(self.username, contact),
                                              self.show_chat_page(self.username, contact)])

            menu.post(self.root.winfo_pointerx(), self.root.winfo_pointery())

        tk.Button(top, text="⋮", command=open_menu).pack(side="right")

        chat = tk.Text(frame, state="disabled")
        chat.pack(fill="both", expand=True)

        self.active_chat = contact
        self.chat_widget = chat

        key = self.ensure_key(contact)
        if not key:
            return

        chat.config(state="normal")
        for sender, msg, _ in get_messages(username, contact):
            try:
                dec = decrypt_message(
                    key,
                    base64.b64decode(msg.encode())
                ).decode()
            except:
                continue
            chat.insert("end", f"{sender}: {dec}\n")
        chat.config(state="disabled")

        bottom = tk.Frame(frame)
        bottom.pack(fill="x")

        entry = tk.Entry(bottom)
        entry.pack(side="left", fill="x", expand=True)

        def send():
            m = entry.get().strip()
            if not m:
                return

            key = self.ensure_key(contact)
            if not key:
                return

            plaintext = m.encode()

            enc = base64.b64encode(
                encrypt_message(key, plaintext)
            ).decode()

            mac = generate_hmac(key, plaintext)

            self.send_json({
                "type": "chat",
                "to": contact,
                "payload": enc,
                "hmac": mac
            })

            save_message(username, contact, enc)

            chat.config(state="normal")
            chat.insert("end", f"You: {m}\n")
            chat.config(state="disabled")

            entry.delete(0, tk.END)
            chat.see("end")

        tk.Button(bottom, text="Send", command=send).pack(side="right")

        self.switch_frame(frame)


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()