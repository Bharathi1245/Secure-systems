import os
import hashlib
import re
import time
import json
import base64

USER_FILE = "users.json"

# =========================
# Password Complexity Check
# =========================
def is_strong_password(password):
    pattern = r'^(?=.*[0-9])(?=.*[!@#$%^&*(),.?":{}|<>]).{12,}$'
    return re.match(pattern, password)


# =========================
# Hash Password
# =========================
def hash_password(password, salt):
    return hashlib.sha256(salt + password.encode()).hexdigest()


# =========================
# Load Users
# =========================
def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, "r") as f:
        return json.load(f)


# =========================
# Save Users
# =========================
def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)


# =========================
# Register
# =========================
def register():
    users = load_users()

    username = input("Enter username: ")

    if username in users:
        print("User already exists.")
        return

    password = input("Enter strong password: ")

    if not is_strong_password(password):
        print("Weak password! Must be 12+ chars, include number & symbol.")
        return

    salt = os.urandom(16)
    hashed = hash_password(password, salt)

    users[username] = {
        "salt": base64.b64encode(salt).decode(),
        "password": hashed
    }

    save_users(users)
    print("User registered successfully.")


# =========================
# Login
# =========================
def login():
    users = load_users()

    username = input("Enter username: ")

    if username not in users:
        print("User not found.")
        return

    password = input("Enter password: ")

    salt = base64.b64decode(users[username]["salt"])
    stored_hash = users[username]["password"]

    hashed = hash_password(password, salt)

    if hashed == stored_hash:
        print("Login successful!")
    else:
        print("Login failed.")
        time.sleep(2)


print("====== Secure Authentication System ======")
print("1. Register")
print("2. Login")

choice = input("Choose option (1/2): ")

if choice == "1":
    register()
elif choice == "2":
    login()
else:
    print("Invalid choice.")
