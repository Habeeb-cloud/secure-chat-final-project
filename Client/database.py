import sqlite3
import os
import getpass

# 🔐 IMPORTS FOR KEYS
from key_exchange import generate_keypair, serialize_public_key
from cryptography.hazmat.primitives import serialization

# force DB to be inside client folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "chat_app.db")


def create_connection():
    return sqlite3.connect(DB_NAME)


def create_tables():
    conn = create_connection()
    cursor = conn.cursor()

    print("Creating tables...")

    # USERS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,
        public_key TEXT,
        private_key TEXT
    )
    """)

    # CONTACTS TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT,
        contact_name TEXT,
        public_key TEXT
    )
    """)

    # 🔥 NEW: MESSAGES TABLE
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

    print("Tables created successfully.")


# =========================
# 🔐 SIGNUP FUNCTION
# =========================
def create_user(username, password):
    conn = create_connection()
    cursor = conn.cursor()

    kp = generate_keypair()

    private_bytes = kp.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_bytes = serialize_public_key(kp.public_key).decode()

    try:
        cursor.execute(
            "INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)",
            (username, password, public_bytes, private_bytes)
        )
        conn.commit()
        print("User created successfully.")
        return True

    except sqlite3.IntegrityError:
        print("Username already exists.")
        return False

    finally:
        conn.close()


# =========================
# 🔐 LOGIN FUNCTION
# =========================
def login_user(username, password):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    user = cursor.fetchone()
    conn.close()

    if user:
        print("Login successful.")
        return True
    else:
        print("Invalid username or password.")
        return False


# =========================
# 🔐 GET USER DATA
# =========================
def get_user(username):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT username, password, public_key, private_key FROM users WHERE username=?",
        (username,)
    )

    user = cursor.fetchone()
    conn.close()

    return user


# =========================
# 📇 CONTACT FUNCTIONS
# =========================
def add_contact(owner, contact_name, public_key=""):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM contacts WHERE owner=? AND contact_name=?",
        (owner, contact_name)
    )

    if cursor.fetchone():
        conn.close()
        return

    cursor.execute(
        "INSERT INTO contacts (owner, contact_name, public_key) VALUES (?, ?, ?)",
        (owner, contact_name, public_key)
    )

    conn.commit()
    conn.close()


def get_contacts(owner):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT contact_name, public_key FROM contacts WHERE owner=?",
        (owner,)
    )

    results = cursor.fetchall()
    conn.close()

    return results


def search_contact(owner, name):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT contact_name FROM contacts WHERE owner=? AND contact_name LIKE ?",
        (owner, f"%{name}%")
    )

    results = cursor.fetchall()
    conn.close()

    return [r[0] for r in results]


# =========================
# 💬 MESSAGE FUNCTIONS (NEW)
# =========================
def save_message(sender, receiver, message):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
        (sender, receiver, message)
    )

    conn.commit()
    conn.close()


def get_messages(user1, user2):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT sender, message, timestamp FROM messages
        WHERE (sender=? AND receiver=?)
        OR (sender=? AND receiver=?)
        ORDER BY timestamp
    """, (user1, user2, user2, user1))

    results = cursor.fetchall()
    conn.close()

    return results


# =========================
# ▶️ TEST MENU
# =========================
if __name__ == "__main__":
    create_tables()

    while True:
        print("\n1. Sign Up")
        print("2. Login")
        print("3. Add Contact (test)")
        print("4. View Contacts (test)")
        print("5. Exit")

        choice = input("Select option: ").strip()

        if choice == "1":
            username = input("Enter username: ").strip()

            while True:
                password = getpass.getpass("Enter password: ")
                confirm = getpass.getpass("Confirm password: ")

                if password != confirm:
                    print("Passwords do not match.")
                else:
                    break

            create_user(username, password)

        elif choice == "2":
            username = input("Enter username: ").strip()

            while True:
                password = getpass.getpass("Enter password: ")

                if login_user(username, password):
                    break
                else:
                    print("Try again.")

        elif choice == "3":
            owner = input("Your username: ")
            contact = input("Contact name: ")
            pubkey = input("Public key (optional): ")

            add_contact(owner, contact, pubkey)
            print("Contact added.")

        elif choice == "4":
            owner = input("Your username: ")
            contacts = get_contacts(owner)

            print("Your contacts:")
            for name, _ in contacts:
                print(f"- {name}")

        elif choice == "5":
            print("Exiting...")
            break

        else:
            print("Invalid option.")