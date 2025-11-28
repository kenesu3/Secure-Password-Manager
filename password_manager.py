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

# Removed: SALT = b'a_unique_salt_for_this_app'
SINGLE_USER_ID = "default_user"

# --- Master Key Validation Requirements ---
MASTER_KEY_REQUIREMENTS = {
    "min_length": 12,
    "uppercase": r"[A-Z]",
    "lowercase": r"[a-z]",
    "number": r"[0-9]",
    "special_char": r"[!@#$%^&*()_+=\-\[\]{};':\"\\|,.<>/?`~]",
}