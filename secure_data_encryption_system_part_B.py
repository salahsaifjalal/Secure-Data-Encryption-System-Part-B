import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64
import json
import os
import time
from datetime import datetime, timedelta

USERS_FILE = "users.json"
SECRETS_FILE = "secrets.json"

# Helpers for password hashing
def hash_pbkdf2(password, salt=b'static_salt', iterations=100000):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations).hex()

# Load and save user/secrets from JSON
def load_data():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            st.session_state.users = json.load(f)
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, 'r') as f:
            st.session_state.secrets = json.load(f)

def save_data():
    with open(USERS_FILE, 'w') as f:
        json.dump(st.session_state.users, f)
    with open(SECRETS_FILE, 'w') as f:
        json.dump(st.session_state.secrets, f)

def generate_key(password: str, salt: bytes = b'static_salt', iterations: int = 100_000) -> bytes:
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(key)

def encrypt_data(text, password):
    cipher = Fernet(generate_key(password))
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, password):
    try:
        cipher = Fernet(generate_key(password))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Initialize session state
if 'auth' not in st.session_state:
    st.session_state.auth = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'users' not in st.session_state:
    st.session_state.users = {}
if 'secrets' not in st.session_state:
    st.session_state.secrets = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}
if 'lockout_until' not in st.session_state:
    st.session_state.lockout_until = {}

load_data()

# Pages
def login_register_page():
    st.title("🔐 Secure Data Encryption System")
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        with st.form("Login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            now = time.time()
            if username in st.session_state.lockout_until and now < st.session_state.lockout_until[username]:
                st.warning("⏳ Too many failed attempts. Try again later.")
                return

            if st.form_submit_button("Login"):
                user = st.session_state.users.get(username)
                if user and user["password"] == hash_pbkdf2(password):
                    st.session_state.auth = True
                    st.session_state.current_user = username
                    st.session_state.failed_attempts[username] = 0
                    st.rerun()
                else:
                    st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
                    if st.session_state.failed_attempts[username] >= 3:
                        st.session_state.lockout_until[username] = now + 60
                        st.error("🔒 Locked out for 1 minute due to multiple failed attempts.")
                    else:
                        st.error("Invalid credentials")

    with tab2:
        with st.form("Register"):
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            if st.form_submit_button("Create Account"):
                if new_user in st.session_state.users:
                    st.error("Username already exists")
                else:
                    st.session_state.users[new_user] = {
                        "password": hash_pbkdf2(new_pass)
                    }
                    save_data()
                    st.success("Account created successfully!")

def home_page():
    st.title("🏠 Welcome to Your Secure Vault")
    st.write("Use the sidebar Menu for Navigation.")
    st.info("All data is stored in a JSON file instead of memory and "+
            "use PBKDF2 hashing instead of SHA-256 for extra security and "+
            "allow multiple users to store and retrieve their own data.")


def store_data_page():
    st.title("🔏 Store Encrypted Data")
    with st.form("store_form"):
        title = st.text_input("Title for Your Secret")
        secret = st.text_area("Enter Secret Data")
        passkey = st.text_input("Create Passkey", type="password")

        if st.form_submit_button("Encrypt & Save"):
            if title and secret and passkey:
                encrypted = encrypt_data(secret, passkey)
                hashed_passkey = hash_pbkdf2(passkey)

                user = st.session_state.current_user
                if user not in st.session_state.secrets:
                    st.session_state.secrets[user] = []

                st.session_state.secrets[user].append({
                    "title": title,
                    "encrypted": encrypted,
                    "passkey_hash": hashed_passkey
                })
                save_data()
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ All fields are required!")

def retrieve_data_page():
    st.title("🔐 Retrieve Your Data")
    user = st.session_state.current_user

    if user not in st.session_state.secrets or len(st.session_state.secrets[user]) == 0:
        st.info("You have no saved data yet.")
        return

    for idx, secret in enumerate(st.session_state.secrets[user]):
        with st.expander(secret["title"]):
            key_id = f"{user}_{idx}"
            passkey = st.text_input(f"Enter Passkey for {secret['title']}", type="password", key=key_id)

            if key_id not in st.session_state.failed_attempts:
                st.session_state.failed_attempts[key_id] = 0

            if passkey:
                hashed_input = hash_pbkdf2(passkey)

                if hashed_input == secret["passkey_hash"]:
                    decrypted = decrypt_data(secret["encrypted"], passkey)
                    if decrypted:
                        st.session_state.failed_attempts[key_id] = 0
                        st.text_area("Decrypted Data", value=decrypted, disabled=True)
                    else:
                        st.error("⚠️ Decryption error.")
                else:
                    st.session_state.failed_attempts[key_id] += 1
                    attempts_left = 3 - st.session_state.failed_attempts[key_id]

                    if attempts_left > 0:
                        st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
                    else:
                        st.error("🔒 Too many failed attempts. Please reauthorize.")
                        st.session_state.auth = False
                        st.session_state.current_user = None
                        st.rerun()

def change_password_page():
    st.title("🔑 Change Password")
    with st.form("change_pass"):
        new_pass = st.text_input("New Password", type="password")
        current_pass = st.text_input("Current Password", type="password")

        if st.form_submit_button("Update Password"):
            user = st.session_state.current_user
            if st.session_state.users[user]["password"] == hash_pbkdf2(current_pass):
                st.session_state.users[user]["password"] = hash_pbkdf2(new_pass)
                save_data()
                st.success("✅ Password updated successfully!")
            else:
                st.error("❌ Current password incorrect.")

def delete_profile_page():
    st.title("🗑️ Delete Account")
    with st.form("delete_form"):
        password = st.text_input("Confirm Password", type="password")
        if st.form_submit_button("Delete My Profile"):
            user = st.session_state.current_user
            if st.session_state.users[user]["password"] == hash_pbkdf2(password):
                del st.session_state.users[user]
                if user in st.session_state.secrets:
                    del st.session_state.secrets[user]
                save_data()
                st.session_state.auth = False
                st.session_state.current_user = None
                st.success("✅ Account deleted successfully.")
                st.rerun()
            else:
                st.error("❌ Incorrect password.")

def main():
    if not st.session_state.auth:
        login_register_page()
        return

    with st.sidebar:
        st.title("🔍 Menu")
        menu = st.radio("Choose", ["Home", "Store Data", "Retrieve Data", "Change Password", "Delete Profile", "Logout"])

    if menu == "Home":
        home_page()
    elif menu == "Store Data":
        store_data_page()
    elif menu == "Retrieve Data":
        retrieve_data_page()
    elif menu == "Change Password":
        change_password_page()
    elif menu == "Delete Profile":
        delete_profile_page()
    elif menu == "Logout":
        st.session_state.auth = False
        st.session_state.current_user = None
        st.rerun()

if __name__ == "__main__":
    main()
