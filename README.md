# Secure Password Manager

## Overview

This application is a secure, local desktop-based password manager developed in Python. It provides encrypted storage for account credentials using modern cryptographic standards. The system enforces a strong master key, uses dynamic salt generation, and stores all encrypted passwords in a local JSON file.

## Features

* Symmetric Encryption (Fernet) for securing stored passwords
* Key Derivation using PBKDF2HMAC with SHA-256 and 480,000 iterations
* Dynamic salt generation stored in `salt.key`
* Strong Master Key requirements (12+ characters with complexity)
* Password strength meter
* Secure password generator using the `secrets` module
* Encrypted local storage in `passwords.json`
* Ability to change master key and re-encrypt stored data
* Search functionality for accounts
* Tkinter GUI for managing accounts
* Auto-lock when inactive for 2 minutes

## Technical Specifications

* Language: Python 3.x
* GUI Framework: Tkinter
* Encryption: Fernet (AES-128 with integrity protection)
* Key Derivation: PBKDF2HMAC (SHA-256)
* Random Number Generator: `secrets.SystemRandom()`
* Data Files:

  * `passwords.json`
  * `secret.key`
  * `salt.key`

## Installation

### Prerequisites

* Python 3.6 or higher
* pip (Python package installer)

### Install Dependencies

```bash
pip install cryptography
```

## Usage

### Running the Application

```bash
password_manager.py
```

The first launch will prompt you to create a master key and will generate the following files:

* `secret.key`
* `salt.key`
* `passwords.json`

These must remain in the same directory for the application to work.

## Building an Executable (.exe)

### Step 1: Install PyInstaller

```bash
pip install pyinstaller
```

### Step 2: Build the Executable

```bash
pyinstaller --onefile --noconsole password_manager.py
```

### Step 3: Locate the Executable

The executable will appear in:

```
dist/password_manager.exe
```

### Important Notes

When running the executable for the first time, it will create:

* `passwords.json`
* `secret.key`
* `salt.key`

These files must remain in the same directory as the executable.
Removing them will permanently delete all stored passwords.

## License

This project is free to modify and enhance.

---