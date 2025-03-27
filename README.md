# ency
 

# 🔒 **VaultSecure – Protect Sensitive Data with Encryption and Access Control**

**VaultSecure** is a Python-based tool designed to **encrypt and decrypt sensitive data** while providing **user authentication and access control**. It ensures data confidentiality with AES encryption and offers automated backups for secure file management.

---

### 🚀 **Features**
- 🔐 **AES-256 Encryption:** Encrypts and decrypts files and folders securely.
- 👥 **User Authentication:** Prevents unauthorized access with username-password verification.
- 🔥 **Backup Management:** Automatically creates backups before encrypting or decrypting files.
- 📁 **File Integrity Check:** Ensures data integrity with SHA-256 hashing.
- 🛠️ **Easy-to-Use Interface:** Command-line interface (CLI) with clear prompts and logs.

---

### 📦 **Project Structure**


---

### 🔥 **Requirements**
Ensure you have Python 3 installed. Install the required dependencies using:
```bash
pip install -r requirements.txt
requirements.txt:

🚀 Usage
Clone the Repository:

bash
Copy
Edit
git clone https://github.com/your-username/VaultSecure.git
cd VaultSecure
Install Dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Run the Program:

bash
Copy
Edit
python vaultsecure.py
🔥 How to Use
User Authentication:

On the first run, create a username and password.

On subsequent runs, you’ll need to authenticate before encrypting/decrypting files.

Encrypting Files:

Select 1 to Encrypt a folder.

Enter the folder path and set a password for encryption.

The program will encrypt all supported files (.txt, .doc) and create backups.

Decrypting Files:

Select 2 to Decrypt a folder.

Enter the folder path and decryption password.

The program will restore the original files and create a backup.

Backup Management:

Automatic backups are created before any encryption or decryption.

You can manually manage or delete old backups.

⚙️ Configuration
You can customize the following settings in config.json:

json
Copy
Edit
{
  "recent_directories": [],
  "max_recent_dirs": 5,
  "backup_enabled": true,
  "backup_location": "backups",
  "key_directory": "keys"
}
backup_enabled: Toggle automatic backups (true/false).

backup_location: Path to backup directory.

max_recent_dirs: Number of recent directories to store.

key_directory: Path to store encryption keys.

🛠️ Error Handling
🔥 Invalid credentials: Prompts with ❌ Access denied. Invalid credentials.

⚠️ Incorrect password: Displays ⚠️ Decryption failed due to wrong password.

🛠️ Invalid file format: Skips unsupported file types and logs the event.

🛡️ Security Tips
Use strong passwords when protecting encryption keys.

Regularly back up your keys and keep them safe.

Ensure you don’t lose your encryption password, as decryption will fail without it.

📌 Contributing
Contributions are welcome!

Fork the repository

Create a new branch

Make your changes

Submit a pull request

📄 License
This project is licensed under the MIT License.

🚀 Author
👤 Devan Muthappa MR
💻 LinkedIn
🔗 GitHub

✅ Thank you for using VaultSecure!
📂 Keep your sensitive data safe and secure with encryption and access control! 🔒

yaml
Copy
Edit
---

✅ This `README.md` is now **ready for GitHub**. You can:
1. Create a `README.md` file in your GitHub repository.
2. Paste this content.
3. Commit and push the changes.

Let me know if you need any modifications or additional features! 🚀
