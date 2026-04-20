import tkinter as tk
from tkinter import messagebox

from database import create_user, login_user, get_contacts, get_messages


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("400x400")

        self.current_frame = None

        self.show_signup()

    # 🔄 SWITCH FRAMES
    def switch_frame(self, new_frame):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = new_frame
        self.current_frame.pack(fill="both", expand=True)

    # ================= SIGN UP PAGE =================
    def show_signup(self):
        frame = tk.Frame(self.root)

        top_frame = tk.Frame(frame)
        top_frame.pack(fill="x")

        login_btn = tk.Button(top_frame, text="Login", command=self.show_login)
        login_btn.pack(side="right", padx=10, pady=10)

        form = tk.Frame(frame)
        form.pack(pady=20)

        tk.Label(form, text="Username").grid(row=0, column=0, sticky="w")
        username_entry = tk.Entry(form)
        username_entry.grid(row=0, column=1)

        tk.Label(form, text="Password").grid(row=1, column=0, sticky="w")
        password_entry = tk.Entry(form, show="*")
        password_entry.grid(row=1, column=1)

        tk.Label(form, text="Confirm Password").grid(row=2, column=0, sticky="w")
        confirm_entry = tk.Entry(form, show="*")
        confirm_entry.grid(row=2, column=1)

        bottom = tk.Frame(frame)
        bottom.pack(fill="x", pady=20)

        def signup_action():
            username = username_entry.get()
            password = password_entry.get()
            confirm = confirm_entry.get()

            if not username or not password:
                messagebox.showerror("Error", "All fields required")
                return

            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return

            success = create_user(username, password)

            if success:
                messagebox.showinfo("Success", "Account created successfully")
                self.show_login()
            else:
                messagebox.showerror("Error", "Username already exists")

        signup_btn = tk.Button(bottom, text="Sign Up", command=signup_action)
        signup_btn.pack(side="right", padx=10)

        self.switch_frame(frame)

    # ================= LOGIN PAGE =================
    def show_login(self):
        frame = tk.Frame(self.root)

        top_frame = tk.Frame(frame)
        top_frame.pack(fill="x")

        back_btn = tk.Button(top_frame, text="Back", command=self.show_signup)
        back_btn.pack(side="right", padx=10, pady=10)

        form = tk.Frame(frame)
        form.pack(pady=30)

        tk.Label(form, text="Username").grid(row=0, column=0, sticky="w")
        username_entry = tk.Entry(form)
        username_entry.grid(row=0, column=1)

        tk.Label(form, text="Password").grid(row=1, column=0, sticky="w")
        password_entry = tk.Entry(form, show="*")
        password_entry.grid(row=1, column=1)

        bottom = tk.Frame(frame)
        bottom.pack(fill="x", pady=20)

        def login_action():
            username = username_entry.get()
            password = password_entry.get()

            if not username or not password:
                messagebox.showerror("Error", "All fields required")
                return

            if login_user(username, password):
                messagebox.showinfo("Success", "Login successful")
                self.show_contacts(username)
            else:
                messagebox.showerror("Error", "Invalid credentials")

        login_btn = tk.Button(bottom, text="Login", command=login_action)
        login_btn.pack(side="right", padx=10)

        self.switch_frame(frame)

    # ================= CONTACTS PAGE =================
    def show_contacts(self, username):
        frame = tk.Frame(self.root)

        top = tk.Frame(frame)
        top.pack(fill="x")

        back_btn = tk.Button(top, text="Back", command=self.show_login)
        back_btn.pack(side="left", padx=10, pady=10)

        add_btn = tk.Button(top, text="+", command=lambda: print("Add Contact Page (next)"))
        add_btn.pack(side="right", padx=10, pady=10)

        tk.Label(frame, text="Contacts", font=("Arial", 14)).pack()

        contacts_list = tk.Listbox(frame)
        contacts_list.pack(fill="both", expand=True, padx=20, pady=10)

        contacts = get_contacts(username)

        for name, _ in contacts:
            contacts_list.insert(tk.END, name)

        def open_chat(event):
            selected = contacts_list.curselection()
            if selected:
                contact_name = contacts_list.get(selected[0])
                self.show_chat_page(username, contact_name)

        contacts_list.bind("<<ListboxSelect>>", open_chat)

        self.switch_frame(frame)

    # ================= CHAT PAGE =================
    def show_chat_page(self, username, contact_name):
        frame = tk.Frame(self.root)

        # TOP BAR
        top = tk.Frame(frame)
        top.pack(fill="x")

        back_btn = tk.Button(top, text="Back",
                             command=lambda: self.show_contacts(username))
        back_btn.pack(side="left", padx=10, pady=10)

        tk.Label(top, text=contact_name, font=("Arial", 12)).pack(side="left", padx=10)

        menu_btn = tk.Button(top, text="⋮",
                             command=lambda: print("Delete/edit coming next"))
        menu_btn.pack(side="right", padx=10)

        # CHAT DISPLAY
        chat_display = tk.Text(frame, state="disabled")
        chat_display.pack(fill="both", expand=True, padx=10, pady=10)

        # LOAD HISTORY (hide encrypted for now)
        messages = get_messages(username, contact_name)

        chat_display.config(state="normal")
        for sender, msg, time in messages:
            chat_display.insert("end", f"{sender}: [encrypted message]\n")
        chat_display.config(state="disabled")

        # INPUT
        bottom = tk.Frame(frame)
        bottom.pack(fill="x")

        msg_entry = tk.Entry(bottom)
        msg_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)

        def send_message():
            message = msg_entry.get().strip()

            if not message:
                return

            chat_display.config(state="normal")
            chat_display.insert("end", f"You: {message}\n")
            chat_display.config(state="disabled")

            msg_entry.delete(0, tk.END)
            chat_display.see("end")  # 🔥 auto scroll

        send_btn = tk.Button(bottom, text="Send", command=send_message)
        send_btn.pack(side="right", padx=5)

        self.switch_frame(frame)


# ================= RUN APP =================
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()