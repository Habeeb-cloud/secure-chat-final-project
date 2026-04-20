import tkinter as tk
from tkinter import messagebox
from database import get_contacts, add_contact, search_contact


class ContactsApp:

    def __init__(self, root, username):
        self.root = root
        self.root.title("Contacts")
        self.root.geometry("600x400")

        self.username = username

        # Title
        tk.Label(root, text="Contacts", font=("Arial", 16)).pack(pady=10)

        # Back button
        tk.Button(root, text="Back", command=self.go_back).place(x=520, y=10)

        # Contact list frame
        self.contact_frame = tk.Frame(root)
        self.contact_frame.pack(pady=20)

        self.load_contacts()

        # Search
        self.search_entry = tk.Entry(root)
        self.search_entry.place(x=400, y=200)

        tk.Button(root, text="Search", command=self.search).place(x=400, y=230)

        # Add button
        tk.Button(root, text="Add", command=self.open_add_contact).place(x=420, y=300)

    def load_contacts(self):
        for widget in self.contact_frame.winfo_children():
            widget.destroy()

        contacts = get_contacts(self.username)

        for i, contact in enumerate(contacts):
            tk.Button(
                self.contact_frame,
                text=contact,
                width=20,
                command=lambda c=contact: self.open_chat(c)
            ).pack(pady=5)

    def search(self):
        name = self.search_entry.get()
        results = search_contact(self.username, name)

        if not results:
            messagebox.showerror("Error", "Contact does not exist")
            return

        self.open_chat(results[0])

    def open_add_contact(self):
        add_window = tk.Toplevel(self.root)
        add_window.title("Add Contact")
        add_window.geometry("300x200")

        tk.Label(add_window, text="Name").pack()
        name_entry = tk.Entry(add_window)
        name_entry.pack()

        tk.Label(add_window, text="Email").pack()
        email_entry = tk.Entry(add_window)
        email_entry.pack()

        def save():
            name = name_entry.get()

            if not name:
                messagebox.showerror("Error", "Enter name")
                return

            add_contact(self.username, name)
            messagebox.showinfo("Success", "Contact added")
            add_window.destroy()
            self.load_contacts()

        tk.Button(add_window, text="Save", command=save).pack(pady=10)

    def open_chat(self, contact):
        messagebox.showinfo("Chat", f"Opening chat with {contact}")
        # 👉 next step: connect to real chat system

    def go_back(self):
        self.root.destroy()
        from login_gui import LoginApp

        new_root = tk.Tk()
        LoginApp(new_root)
        new_root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    app = ContactsApp(root, "habeeb")  # test user
    root.mainloop()