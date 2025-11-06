🔐 Secure P2P File Sharing System
📖 Overview

A lightweight peer-to-peer (P2P) file sharing application that enables secure file transfer between two devices.
It uses AES-GCM encryption and password-based authentication to ensure data confidentiality and integrity.
The project includes a Flask-based server and a Python Requests client, supporting both file upload and download over an encrypted channel.

⚙️ Features

🔒 End-to-End Encryption (AES-GCM) for secure file transfers

🔑 Password-Based Authentication between two trusted peers

📤📥 Supports Upload and Download modes

🧠 Dynamic Command-Line Client (choose file, action, and server address)

💡 Lightweight Design — only 3 Python files

🧰 Tech Stack

Language: Python

Libraries: Flask, Cryptography, Requests

Encryption: AES-GCM, Scrypt key derivation, SHA-256 file integrity

🛠️ Installation
1️⃣ Clone the Repository
git clone https://github.com/yourusername/secure-p2p.git
cd secure-p2p

2️⃣ Install Dependencies
pip install flask cryptography requests

🚀 How to Use
🖥️ Start the Secure Server

Run the server first (this acts as the host peer):

python secure_server.py


Output should look like:

[*] Secure Flask Server running (1:1 mode) on port 5002
 * Running on http://127.0.0.1:5002

📱 Use the Client
▶️ Upload a File
python secure_client.py upload example.txt


If the file doesn’t exist, it will automatically be created for testing.

⬇️ Download a File
python secure_client.py download example.txt --out copy.txt

🌐 Connect Across Devices (LAN)

If running on two machines:

Find the server’s IP address (e.g., 192.168.1.5)

Run the client with the --url option:

python secure_client.py --url http://192.168.1.5:5002 upload example.txt

🔒 Security Highlights

End-to-end encryption using AES-GCM

Password-derived encryption keys using Scrypt

Integrity validation via SHA-256

Restrictive 1-to-1 connection model (single trusted client)

🧩 Project Structure
secure_p2p/
│
├── secure_server.py   # Flask secure file server
├── secure_client.py   # Python client for upload/download
└── secure_utils.py    # AES-GCM encryption, hashing, and helpers

🧠 Description (for Resume)

Developed a lightweight peer-to-peer file sharing application enabling secure file transfer between two devices. Implemented end-to-end encryption (AES-GCM) and password-based authentication to ensure data confidentiality and integrity. Built the server using Flask and the client using Python Requests, supporting both file upload and download over an encrypted channel.

📸 Example Output
[+] Handshake successful
[+] Upload successful: File 'example.txt' uploaded successfully
[+] Downloaded and decrypted 'copy.txt' (SHA256=abc123...)

🧾 License

This project is released under the MIT License.
Feel free to use, modify, and share it with proper credit.
