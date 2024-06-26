import os
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Constants
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100000

def generate_salt():
    return os.urandom(SALT_SIZE)

def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def encrypt_data(key, data):
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_data(key, encrypted_data):
    iv = encrypted_data[:IV_SIZE]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded_data = decryptor.update(encrypted_data[IV_SIZE:]) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_data = encrypt_data(key, data)
    with open(file_path, 'wb') as f:  # Overwrite the original file
        f.write(encrypted_data)

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_data(key, encrypted_data)
    with open(file_path, 'wb') as f:  # Overwrite the original file
        f.write(decrypted_data)

def encrypt_action():
    file_path = input("Enter the path of the file to encrypt: ")
    if not file_path:
        return

    passphrase = getpass.getpass("Enter a passphrase for this file: ")
    salt = generate_salt()
    key = derive_key(passphrase, salt)

    # Generate a random File Encryption Key (FEK)
    fek = os.urandom(KEY_SIZE)

    # Encrypt the FEK with the derived key
    encrypted_fek = encrypt_data(key, fek)

    # Store the encrypted FEK and salt in a separate file
    fek_file_path = file_path + '.fek'
    with open(fek_file_path, 'wb') as f:
        f.write(salt + encrypted_fek)

    # Encrypt the file using the FEK
    encrypt_file(file_path, fek)
    print(f"File '{file_path}' encrypted successfully. FEK stored in '{fek_file_path}'.")

def decrypt_action():
    file_path = input("Enter the path of the file to decrypt: ")
    if not file_path:
        return

    passphrase = getpass.getpass("Enter the passphrase for this file: ")

    # Read the encrypted FEK and salt from the separate file
    fek_file_path = file_path + '.fek'
    if not os.path.isfile(fek_file_path):
        print(f"FEK file '{fek_file_path}' does not exist. Please check the file path and try again.")
        return

    with open(fek_file_path, 'rb') as f:
        salt = f.read(SALT_SIZE)
        encrypted_fek = f.read()

    key = derive_key(passphrase, salt)

    # Decrypt the FEK with the derived key
    fek = decrypt_data(key, encrypted_fek)

    # Decrypt the file using the FEK
    decrypt_file(file_path, fek)

    # Delete the FEK file after decryption
    os.remove(fek_file_path)
    print(f"File '{file_path}' decrypted successfully. FEK file '{fek_file_path}' deleted.")

def main():
    action = input("Do you want to (e)ncrypt or (d)ecrypt a file? ")
    if action.lower() == 'e':
        encrypt_action()
    elif action.lower() == 'd':
        decrypt_action()
    else:
        print("Invalid action. Please enter 'e' to encrypt or 'd' to decrypt.")

if __name__ == "__main__":
    main()
