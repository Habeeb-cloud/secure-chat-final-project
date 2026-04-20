import tkinter as tk
from tkinter import messagebox
from database import login_user, create_tables

# ensure DB exists
create_tables()


class LoginApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        self.root.geometry("400x300")

        # Title
        tk.Label(root, text="Login", font=("Arial", 16)).pack(pady=20)

        # Username (Email)
        tk.Label(root, text="Email").pack()
        self.username_entry = tk.Entry(root)
        self.username_entry.pack(pady=5)

        # Password
        tk.Label(root, text="Password").pack()
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack(pady=5)

        # Login Button
        tk.Button(root, text="Login", command=self.login).pack(pady=10)

        # Back to Signup
        tk.Button(root, text="Create Account", command=self.open_signup).pack()

    # ================= LOGIN =================
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if login_user(username, password):
            messagebox.showinfo("Success", "Login successful!")
            self.root.destroy()

            # 👉 Next: open chat window (we'll do this next)

        else:
            messagebox.showerror("Error", "Invalid credentials")

    # ================= OPEN SIGNUP =================
    def open_signup(self):
        self.root.destroy()
        from signup_gui import SignupApp

        new_root = tk.Tk()
        SignupApp(new_root)
        new_root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()