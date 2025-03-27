import sys
import os
import shutil
import logging
import getpass
import hashlib
import json
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

class VaultSecure:
    def __init__(self):
        self.base_dir = r"C:\Users\Devan\Desktop\VaultSecure"
        self.users_file = os.path.join(self.base_dir, "users.json")
        self.config_file = os.path.join(self.base_dir, "config.json")
        self.setup_logging()
        self.load_config()
        self.authenticate_user()

    def setup_logging(self):
        """Configure logging for the application."""
        log_dir = os.path.join(self.base_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, f"vaultsecure_{datetime.now().strftime('%Y%m%d')}.log")
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    def authenticate_user(self):
        """Authenticate the user with username and password."""
        if not os.path.exists(self.users_file):
            self.create_user()

        with open(self.users_file, 'r') as f:
            users = json.load(f)

        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password: ").strip()

        if username in users and users[username] == hashlib.sha256(password.encode()).hexdigest():
            logging.info(f"User '{username}' authenticated successfully.")
            print("\n✅ Access granted.")
        else:
            logging.warning(f"Failed login attempt for '{username}'.")
            print("\n❌ Invalid credentials. Exiting...")
            sys.exit()

    def create_user(self):
        """Create a new user with a password."""
        print("\n🔒 Setting up initial user.")
        username = input("Create username: ").strip()
        password = getpass.getpass("Create password: ").strip()

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with open(self.users_file, 'w') as f:
            json.dump({username: hashed_password}, f)

        logging.info(f"User '{username}' created successfully.")
        print("\n✅ User created. Please restart the program.")

    def load_config(self):
        """Load or create configuration file."""
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = {
                "recent_directories": [],
                "max_recent_dirs": 5,
                "backup_enabled": True,
                "backup_location": os.path.join(self.base_dir, "backups"),
                "key_directory": os.path.join(self.base_dir, "keys")
            }
            self.save_config()

    def save_config(self):
        """Save configuration to file."""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive AES-256 encryption key from password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def generate_key(self, password: str) -> tuple:
        """Generate a new AES-256 key with salt."""
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        return key, salt

    def create_backup(self, file_path: str):
        """Create a backup before encryption/decryption."""
        if not self.config["backup_enabled"]:
            return

        backup_dir = Path(self.config["backup_location"])
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"{Path(file_path).name}_{timestamp}.backup"

        shutil.copy2(file_path, backup_path)
        logging.info(f"Backup created: {backup_path}")

    def encrypt_file(self, file_path: str, password: str):
        """Encrypt a single file using AES-256."""
        try:
            self.create_backup(file_path)

            salt = os.urandom(16)
            key = self.derive_key(password, salt)

            with open(file_path, 'rb') as f:
                plaintext = f.read()

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            encrypted_file = file_path + '.enc'
            with open(encrypted_file, 'wb') as f:
                f.write(salt + iv + ciphertext)

            os.remove(file_path)
            logging.info(f"Encrypted: {file_path}")
        except Exception as e:
            logging.error(f"Encryption failed for {file_path}: {e}")

    def decrypt_file(self, file_path: str, password: str):
        """Decrypt a single file using AES-256."""
        try:
            self.create_backup(file_path)

            with open(file_path, 'rb') as f:
                data = f.read()

            salt = data[:16]
            iv = data[16:32]
            ciphertext = data[32:]

            key = self.derive_key(password, salt)

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            decrypted_file = file_path.replace('.enc', '')
            with open(decrypted_file, 'wb') as f:
                f.write(plaintext)

            os.remove(file_path)
            logging.info(f"Decrypted: {file_path}")
        except Exception as e:
            logging.error(f"Decryption failed for {file_path}: {e}")

    def process_files(self, dir_path: str, password: str, encrypt: bool):
        """Process multiple files for encryption or decryption."""
        dir_path = Path(dir_path)
        if not dir_path.exists():
            logging.error(f"Directory not found: {dir_path}")
            return

        for file_path in dir_path.rglob('*'):
            if file_path.is_file():
                if encrypt and not file_path.suffix == '.enc':
                    self.encrypt_file(str(file_path), password)
                elif not encrypt and file_path.suffix == '.enc':
                    self.decrypt_file(str(file_path), password)

def display_banner():
    """Display the application banner."""
    return '''
  ██████  ██    ██  ██████  ██    ██ ███████ ██████  
 ██    ██ ██    ██ ██    ██ ██    ██ ██      ██   ██ 
 ██    ██ ██    ██ ██    ██ ██    ██ █████   ██████  
 ██    ██ ██    ██ ██    ██ ██    ██ ██      ██   ██ 
  ██████   ██████   ██████   ██████  ███████ ██   ██ 

 <1> Encrypt a folder
 <2> Decrypt a folder
 <3> Exit
'''

def main():
    vault = VaultSecure()

    while True:
        print(display_banner())
        choice = input("Choose an option: ")

        if choice == "1":
            folder = input("Folder to encrypt: ")
            password = getpass.getpass("Enter encryption password: ")
            vault.process_files(folder, password, encrypt=True)

        elif choice == "2":
            folder = input("Folder to decrypt: ")
            password = getpass.getpass("Enter decryption password: ")
            vault.process_files(folder, password, encrypt=False)

        elif choice == "3":
            break

        else:
            print("Invalid option. Try again!")

if __name__ == "__main__":
    main()
