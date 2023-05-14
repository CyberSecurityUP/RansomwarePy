import os
import tkinter as tk
from tkinter import simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from getpass import getpass
from base64 import urlsafe_b64encode
import os

# Define the directory to encrypt
directory_to_encrypt = 'C:\\Users\\Public\\test'

# Hardcoded password for encryption
password_encryption = 'test'  # CHANGE THIS!

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

# Encrypt a file
def encrypt_file(key, file):
    fernet = Fernet(key)
    with open(file, 'rb') as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    with open(file + '.encrypted', 'wb') as f:
        f.write(encrypted_data)


# Encrypt all files in a directory
def encrypt_directory(password, directory):
    key = get_key_from_password(password)
    for foldername, subfolders, filenames in os.walk(directory):
        for filename in filenames:
            encrypt_file(key, os.path.join(foldername, filename))



# Main execution
encrypt_directory(password_encryption, directory_to_encrypt)
