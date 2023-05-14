import os
import tkinter as tk
from tkinter import simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode

# Define the directory to decrypt
directory_to_decrypt = 'C:\\Users\\Public\\test'

# Generate a key from the password
def get_key_from_password(password):
    password = password.encode()  # Convert to type bytes
    salt = b'\x00'*16  # This should be random and secret, but we're simplifying for this example
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
    return key

# Decrypt a file
def decrypt_file(key, file):
    fernet = Fernet(key)
    with open(file, 'rb') as f:
        encrypted_data = f.read()
    data = fernet.decrypt(encrypted_data)
    with open(file[:-10], 'wb') as f:  # Remove '.encrypted' from filename
        f.write(data)

# Decrypt all files in a directory
def decrypt_directory(password, directory):
    key = get_key_from_password(password)
    for foldername, subfolders, filenames in os.walk(directory):
        for filename in filenames:
            if filename.endswith('.encrypted'):
                decrypt_file(key, os.path.join(foldername, filename))

# Create a simple tkinter dialog to get the password
def get_password():
    root = tk.Tk()
    root.withdraw()
    password = simpledialog.askstring("Password", "Enter password:", show='*')
    return password

# Main execution
password = get_password()
decrypt_directory(password, directory_to_decrypt)
