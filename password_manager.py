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

    def add_account(self, account_name: str, username: str, password: str) -> bool:
        """Adds a new encrypted account."""
        if not all([account_name, username, password]):
            return False
        try:
            encrypted_password = self.encrypt_password(password)
            new_account = {
                "account_name": account_name,
                "username": username,
                "password": encrypted_password
            }
            self.accounts.append(new_account)
            self.save_data()
            return True
        except Exception as e:
            print(f"Error adding account: {e}")
            return False

    def get_all_accounts(self):
        """Returns all accounts (without passwords)."""
        return [(acc["account_name"], acc["username"]) for acc in self.accounts]

    def get_account_password(self, index: int) -> str:
        """Returns the decrypted password for an account at the given index."""
        if 0 <= index < len(self.accounts):
            encrypted_pass = self.accounts[index]["password"]
            return self.decrypt_password(encrypted_pass)
        return None

    def delete_account(self, index: int) -> bool:
        """Deletes an account at the given index."""
        if 0 <= index < len(self.accounts):
            del self.accounts[index]
            self.save_data()
            return True
        return False

    def search_accounts(self, keyword: str):
        """Searches for accounts by name or username."""
        keyword = keyword.lower()
        results = []
        for i, acc in enumerate(self.accounts):
            if keyword in acc["account_name"].lower() or keyword in acc["username"].lower():
                results.append((i, acc["account_name"], acc["username"]))
        return results


def generate_secure_password(length, use_upper, use_lower, use_digits, use_special):
    """Generates a secure random password based on criteria using the secrets module."""
    characters = ""
    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation

    if not characters:
        return ""

    # Ensure at least one of each selected type is present
    password = []
    if use_upper:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        password.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        password.append(secrets.choice(string.digits))
    if use_special:
        password.append(secrets.choice(string.punctuation))

    # Fill the rest of the length
    remaining_length = length - len(password)
    if remaining_length > 0:
        password.extend(secrets.choice(characters) for _ in range(remaining_length))

    secrets.SystemRandom().shuffle(password)
    return "".join(password)


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        # Increased default geometry to ensure all elements are visible
        self.root.geometry("850x650")
        self.root.resizable(True, True)

        style = ttk.Style()
        style.theme_use('clam')

        # Define custom styles for buttons
        style.configure('Accent.TButton', foreground='white', background='#4CAF50')
        style.map('Accent.TButton', background=[('active', '#45a049')])
        style.configure('Danger.TButton', foreground='white', background='#F44336')
        style.map('Danger.TButton', background=[('active', '#d32f2f')])

        self.manager = PasswordManager()
        self.current_search_results = []

        # Start directly with the master key window
        self.setup_master_password_window()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        """Handles the window closing event."""
        self.root.destroy()

    # --- Master Key UI ---
    def setup_master_password_window(self):
        """Creates a dialog to set/enter the master password."""
        # Clear the root window
        for widget in self.root.winfo_children():
            widget.destroy()

        self.master_key_frame = ttk.Frame(self.root, padding="20")
        self.master_key_frame.pack(expand=True, fill='both')

        is_key_set = os.path.exists(KEY_FILE)

        if is_key_set:
            ttk.Label(self.master_key_frame, text="Enter Master Key to Unlock Passwords:",
                      font=("Arial", 16, "bold")).pack(pady=10)
            confirm_entry = None
        else:
            ttk.Label(self.master_key_frame, text="Set New Master Key for Encryption:",
                      font=("Arial", 16, "bold")).pack(pady=10)

            # Display requirements
            req_text = "Master Key Requirements:\n"
            req_text += f"- Minimum {MASTER_KEY_REQUIREMENTS['min_length']} characters\n"
            req_text += "- At least 1 uppercase letter (A-Z)\n"
            req_text += "- At least 1 lowercase letter (a-z)\n"
            req_text += "- At least 1 number (0-9)\n"
            req_text += "- At least 1 special character (!@#$%^& etc.)"
            ttk.Label(self.master_key_frame, text=req_text, justify=tk.LEFT, foreground="gray").pack(pady=5)

            # Confirm Master Key Entry
            confirm_frame, confirm_entry = create_password_entry(self.master_key_frame, "Confirm Key:", width=25)
            confirm_frame.pack(pady=5)

        # Master Key Entry
        master_key_frame, master_key_entry = create_password_entry(self.master_key_frame, "Master Key:", width=25)
        master_key_frame.pack(pady=5)
        master_key_entry.focus()

        def set_master_key():
            master_key = master_key_entry.get()

            if not is_key_set:
                # Validation for setting a new key
                unmet_requirements = check_master_key_strength(master_key)
                if unmet_requirements:
                    messagebox.showerror("Weak Master Key",
                                         "Your Master Key does not meet the following requirements:\n- " + "\n- ".join(
                                             unmet_requirements))
                    return

                confirm = confirm_entry.get()
                if master_key != confirm:
                    messagebox.showerror("Error", "Master Keys do not match.")
                    return

            if not master_key:
                messagebox.showerror("Error", "Master Key cannot be empty.")
                return

            if self.manager.load_key(master_key):
                self.manager.load_data()
                messagebox.showinfo("Success", "Passwords unlocked!")
                self.master_key_frame.destroy()
                self.create_main_ui()
            else:
                messagebox.showerror("Error", "Incorrect Master Key.")

        button_frame = ttk.Frame(self.master_key_frame)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Unlock/Set Key", command=set_master_key, style='Accent.TButton').pack()

    def create_main_ui(self):
        """Creates the main user interface."""
        # Clear the root window
        for widget in self.root.winfo_children():
            widget.destroy()

        # --- Header Frame (Title, Search, Lock/Change Key) ---
        header_frame = ttk.Frame(self.root, padding="10")
        header_frame.pack(pady=0, padx=10, fill=tk.X)

        # Title
        title_label = ttk.Label(header_frame, text=f"🔐 Secure Password Manager", font=("Arial", 18, "bold"))
        title_label.pack(side=tk.LEFT, padx=10)

        # Search Bar
        search_frame = ttk.Frame(header_frame)
        search_frame.pack(side=tk.LEFT, padx=20)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind("<KeyRelease>", lambda e: self.on_search())

        ttk.Button(search_frame, text="Search", command=self.on_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Clear", command=self.clear_search).pack(side=tk.LEFT, padx=5)

        # Lock/Change Key Buttons
        header_buttons_frame = ttk.Frame(header_frame)
        header_buttons_frame.pack(side=tk.RIGHT, padx=10)

        ttk.Button(header_buttons_frame, text="Change Master Key", command=self.change_master_key_dialog).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(header_buttons_frame, text="Lock", command=self.handle_lock, style='Danger.TButton').pack(
            side=tk.LEFT, padx=5)

        # --- Account List Frame ---
        list_frame = ttk.Frame(self.root, padding="10")
        list_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        ttk.Label(list_frame, text="Your Accounts:", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))

        # Listbox with scrollbar
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Use Monospace font (Courier) for alignment
        self.accounts_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, height=12, font=("Courier", 10))
        self.accounts_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.accounts_listbox.yview)

        self.refresh_accounts_list()

        # --- Button Frame ---
        button_frame = ttk.Frame(self.root, padding="10")
        button_frame.pack(pady=0, padx=10, fill=tk.X)

        ttk.Button(button_frame, text="Add Account", command=self.add_account_dialog, style='Accent.TButton').pack(
            side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Password", command=self.view_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Account", command=self.delete_account_dialog,
                   style='Danger.TButton').pack(side=tk.LEFT, padx=5)

    def refresh_accounts_list(self):
        """Refreshes the accounts listbox."""
        self.accounts_listbox.delete(0, tk.END)
        accounts = self.manager.get_all_accounts()

        # Determine max length for alignment
        max_name_len = max([len(name) for name, _ in accounts] or [20])  # Default to 20 for header

        # Header for alignment
        header = f"{'Account Name':<{max_name_len + 2}} | {'Username/Email'}"
        self.accounts_listbox.insert(tk.END, header)
        self.accounts_listbox.insert(tk.END, "-" * len(header))

        for name, username in accounts:
            # Use f-string formatting for fixed-width columns
            line = f"{name:<{max_name_len + 2}} | {username}"
            self.accounts_listbox.insert(tk.END, line)

    def on_search(self):
        """Handles the search functionality."""
        keyword = self.search_entry.get()
        if not keyword:
            self.clear_search()
            return

        self.accounts_listbox.delete(0, tk.END)
        self.current_search_results = self.manager.search_accounts(keyword)

        accounts = [(name, username) for _, name, username in self.current_search_results]
        max_name_len = max([len(name) for name, _ in accounts] or [20])

        # Header for alignment
        header = f"{'Account Name':<{max_name_len + 2}} | {'Username/Email'}"
        self.accounts_listbox.insert(tk.END, header)
        self.accounts_listbox.insert(tk.END, "-" * len(header))

        if self.current_search_results:
            for _, name, username in self.current_search_results:
                line = f"{name:<{max_name_len + 2}} | {username}"
                self.accounts_listbox.insert(tk.END, line)
        else:
            self.accounts_listbox.insert(tk.END, "No accounts found.")

    def clear_search(self):
        """Clears the search and refreshes the list."""
        self.search_entry.delete(0, tk.END)
        self.current_search_results = []
        self.refresh_accounts_list()