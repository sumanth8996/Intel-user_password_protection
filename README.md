
# File Encryption/Decryption Tool

This project is a simple file encryption and decryption tool built using Python and the `cryptography` library. It allows you to encrypt and decrypt files with a passphrase.

## Features

- Encrypt files using AES encryption.
- Decrypt files using the provided passphrase.
- Store the encrypted File Encryption Key (FEK) and salt in a separate file.

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/yourusername/file-encryption-tool.git
    cd file-encryption-tool
    ```

2. **Install the required dependencies:**

    Make sure you have Python installed. Then, install the required Python packages using pip:

    ```sh
    pip install cryptography
    ```

## Usage

1. **Run the application:**

    ```sh
    python file_encryption_tool.py
    ```

2. **Encrypt a file:**

    - Run the script and choose the encryption option.
    - Enter the path of the file you want to encrypt.
    - Enter a passphrase for encryption.
    - The file will be encrypted, and the FEK and salt will be stored in a separate file with the `.fek` extension.

3. **Decrypt a file:**

    - Run the script and choose the decryption option.
    - Enter the path of the file you want to decrypt.
    - Enter the passphrase used for encryption.
    - The file will be decrypted, and the `.fek` file will be deleted.

## Code Overview

### Key Functions

- **`generate_salt()`**: Generates a random salt.
- **`derive_key(passphrase, salt)`**: Derives a key from the passphrase and salt using PBKDF2HMAC.
- **`encrypt_data(key, data)`**: Encrypts data using AES encryption.
- **`decrypt_data(key, encrypted_data)`**: Decrypts data using AES encryption.
- **`encrypt_file(file_path, key)`**: Encrypts a file using the provided key.
- **`decrypt_file(file_path, key)`**: Decrypts a file using the provided key.

### Main Functions

- **`encrypt_action()`**: Handles the encryption process.
- **`decrypt_action()`**: Handles the decryption process.
- **`main()`**: Entry point of the script, prompts the user to choose between encryption and decryption.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [cryptography](https://cryptography.io/en/latest/) library for providing the cryptographic functions.

## Contact

For any questions or suggestions, please contact [your-email@example.com](mailto:your-email@example.com).

