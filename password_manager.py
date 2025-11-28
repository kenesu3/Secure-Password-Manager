import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import base64
import re
import string
import secrets # Use secrets for secure random generation
import threading
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
DATA_FILE = "passwords.json"
KEY_FILE = "secret.key"
SALT_FILE = "salt.key" # New constant for salt file

# Removed: SALT = b'a_unique_salt_for_this_app' - Changed to a dynamic salt hashing
SINGLE_USER_ID = "default_user"

# --- Master Key Validation Requirements ---
MASTER_KEY_REQUIREMENTS = {
    "min_length": 12,
    "uppercase": r"[A-Z]",
    "lowercase": r"[a-z]",
    "number": r"[0-9]",
    "special_char": r"[!@#$%^&*()_+=\-\[\]{};':\"\\|,.<>/?`~]",
}


def calculate_password_strength(password: str) -> int:
    """Calculates a password strength score (0-100)."""
    score = 0
    length = len(password)

    # Length bonus (max 25 points for length > 12)
    score += min(25, length * 2)

    # Character set bonuses (max 60 points)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+=\-\[\]{};:\'"\\|,.<>/?`~]', password))

    char_types = sum([has_upper, has_lower, has_digit, has_special])
    score += char_types * 15

    # Simple entropy bonus (max 15 points)
    if length > 8 and char_types >= 3:
        score += 15

    return max(0, min(100, score))

def get_strength_category(score: int) -> tuple[str, str]:
    """Returns the strength category and color."""
    if score < 40:
        return "Weak", "red"
    elif score < 65:
        return "Medium", "orange"
    elif score < 85:
        return "Strong", "green"
    else:
        return "Very Strong", "blue"

def check_master_key_strength(key: str) -> list[str]:
    """Checks the master key against the defined requirements and returns a list of unmet requirements."""
    unmet = []

    if len(key) < MASTER_KEY_REQUIREMENTS["min_length"]:
        unmet.append(f"Minimum {MASTER_KEY_REQUIREMENTS['min_length']} characters")

    if not re.search(MASTER_KEY_REQUIREMENTS["uppercase"], key):
        unmet.append("At least 1 uppercase letter (A-Z)")

    if not re.search(MASTER_KEY_REQUIREMENTS["lowercase"], key):
        unmet.append("At least 1 lowercase letter (a-z)")

    if not re.search(MASTER_KEY_REQUIREMENTS["number"], key):
        unmet.append("At least 1 number (0-9)")

    if not re.search(MASTER_KEY_REQUIREMENTS["special_char"], key):
        unmet.append("At least 1 special character (!@#$%^& etc.)")

    return unmet

# --- Helper Function for Password Visibility Toggle ---
def create_password_entry(parent, label_text, width=30):
    """Creates a label, entry field, and show/hide button for a password."""
    # Frame to hold the label, entry, and button
    container_frame = ttk.Frame(parent)

    ttk.Label(container_frame, text=label_text, width=12, anchor=tk.W).pack(side=tk.LEFT, padx=5)

    entry = ttk.Entry(container_frame, show="*", width=width)
    entry.pack(side=tk.LEFT, padx=5)

    # Toggle function
    def toggle_visibility():
        if entry.cget('show') == '*':
            entry.config(show='')
            show_btn.config(text="Hide")
        else:
            entry.config(show='*')
            show_btn.config(text="Show")

    show_btn = ttk.Button(container_frame, text="Show", command=toggle_visibility, width=5)
    show_btn.pack(side=tk.LEFT, padx=5)

    return container_frame, entry


class PasswordManager:
    def __init__(self):
        self.accounts = []
        self.key = None
        self.fernet = None
        self.logged_in_user = SINGLE_USER_ID  # Fixed user

        # --- Dynamic Salt Implementation ---
        if os.path.exists(SALT_FILE):
            with open(SALT_FILE, "rb") as f:
                self.salt = f.read()
        else:
            self.salt = os.urandom(16)
            with open(SALT_FILE, "wb") as f:
                f.write(self.salt)
            # Optionally set file permissions to 0o600
            try:
                os.chmod(SALT_FILE, 0o600)
            except Exception as e:
                print(f"Warning: Could not set file permissions for {SALT_FILE}: {e}")

    def _derive_key(self, master_password: str) -> bytes:
        """Derives a Fernet key from the master password using PBKDF2HMAC."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,  # Use dynamic salt
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    def load_key(self, password: str) -> bool:
        """Loads the encryption key from a file or attempts to derive it."""
        if os.path.exists(KEY_FILE):
            try:
                with open(KEY_FILE, "rb") as f:
                    stored_key = f.read()

                # Verify if the provided password can generate the stored key
                derived_key = self._derive_key(password)
                if derived_key == stored_key:
                    self.key = derived_key
                    self.fernet = Fernet(self.key)
                    return True
                else:
                    return False  # Incorrect password
            except Exception:
                return False  # Key file corrupted
        else:
            # No key file exists, set a new one
            self.key = self._derive_key(password)
            with open(KEY_FILE, "wb") as f:
                f.write(self.key)
            self.fernet = Fernet(self.key)
            return True

    def update_key(self, new_master_key: str) -> bool:
        """Updates the master key, re-encrypts all data, and saves the new key."""
        try:
            # 1. Derive the new key
            new_key = self._derive_key(new_master_key)
            new_fernet = Fernet(new_key)

            # 2. Decrypt all accounts with the old key
            decrypted_accounts = []
            for acc in self.accounts:
                decrypted_pass = self.decrypt_password(acc["password"])
                if decrypted_pass == "DECRYPTION FAILED":
                    raise Exception("Failed to decrypt existing data with current key.")
                decrypted_accounts.append({
                    "account_name": acc["account_name"],
                    "username": acc["username"],
                    "password": decrypted_pass
                })

            # 3. Encrypt all accounts with the new key
            self.accounts = []
            for acc in decrypted_accounts:
                encrypted_pass = new_fernet.encrypt(acc["password"].encode()).decode()
                self.accounts.append({
                    "account_name": acc["account_name"],
                    "username": acc["username"],
                    "password": encrypted_pass
                })

            # 4. Update the key file
            with open(KEY_FILE, "wb") as f:
                f.write(new_key)

            # 5. Update the in-memory key and Fernet object
            self.key = new_key
            self.fernet = new_fernet

            # 6. Save the re-encrypted data
            self.save_data()

            return True
        except Exception as e:
            print(f"Error updating master key: {e}")
            return False
    def load_data(self):
        """Loads encrypted account data from the JSON file."""
        if not self.key:
            return

        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r") as f:
                    data = json.load(f)
                    # Load accounts for the single user
                    self.accounts = data.get(SINGLE_USER_ID, [])
            except json.JSONDecodeError:
                self.accounts = []
            except Exception:
                self.accounts = []
        else:
            self.accounts = []

    def save_data(self):
        """Saves the current account data to the JSON file."""
        if not self.key:
            return False

        all_data = {}
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r") as f:
                    all_data = json.load(f)
            except json.JSONDecodeError:
                pass  # Start with empty data if file is corrupted

        # Update only the single user's accounts
        all_data[SINGLE_USER_ID] = self.accounts

        try:
            with open(DATA_FILE, "w") as f:
                json.dump(all_data, f, indent=4)
            return True
        except Exception:
            return False

    def encrypt_password(self, password: str) -> str:
        """Encrypts a password using Fernet."""
        if not self.fernet:
            raise Exception("Fernet object not initialized.")
        token = self.fernet.encrypt(password.encode())
        return token.decode()

    def decrypt_password(self, encrypted_password: str) -> str:
        """Decrypts an encrypted password using Fernet."""
        if not self.fernet:
            raise Exception("Fernet object not initialized.")
        try:
            decrypted = self.fernet.decrypt(encrypted_password.encode())
            return decrypted.decode()
        except Exception:
            return "DECRYPTION FAILED"