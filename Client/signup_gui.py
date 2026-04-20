import tkinter as tk
from tkinter import messagebox
from database import create_user


class SignupApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Create Account")
        self.root.geometry("600x400")

        # Title
        tk.Label(root, text="Create account", font=("Arial", 16)).pack(pady=10)

        # Top right login button
        tk.Button(root, text="Login", command=self.open_login).place(x=520, y=10)

        # Form frame
        form_frame = tk.Frame(root)
        form_frame.pack(pady=30)

        # First Name
        tk.Label(form_frame, text="First name").grid(row=0, column=0, padx=20, pady=10)
        self.first_name = tk.Entry(form_frame)
        self.first_name.grid(row=0, column=1)

        # Last Name
        tk.Label(form_frame, text="Last name").grid(row=0, column=2, padx=20)
        self.last_name = tk.Entry(form_frame)
        self.last_name.grid(row=0, column=3)

        # Email
        tk.Label(form_frame, text="Email").grid(row=1, column=0, pady=10)
        self.email = tk.Entry(form_frame)
        self.email.grid(row=1, column=1)

        # Password
        tk.Label(form_frame, text="Password").grid(row=2, column=0, pady=10)
        self.password = tk.Entry(form_frame, show="*")
        self.password.grid(row=2, column=1)

        # Confirm Password
        tk.Label(form_frame, text="Confirm password").grid(row=3, column=0, pady=10)
        self.confirm_password = tk.Entry(form_frame, show="*")
        self.confirm_password.grid(row=3, column=1)

        # Sign in button (bottom right)
        tk.Button(root, text="Sign in", command=self.signup).place(x=500, y=350)

    # ================= SIGN UP =================
    def signup(self):
        email = self.email.get()
        password = self.password.get()
        confirm = self.confirm_password.get()

        if not email or not password:
            messagebox.showerror("Error", "Fill all fields")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return

        # using email as username
        if create_user(email, password):
            messagebox.showinfo("Success", "Account created!")
            self.open_login()
        else:
            messagebox.showerror("Error", "Account already exists")

    # ================= OPEN LOGIN =================
    def open_login(self):
        self.root.destroy()
        from login_gui import LoginApp

        new_root = tk.Tk()
        LoginApp(new_root)
        new_root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    app = SignupApp(root)
    root.mainloop()