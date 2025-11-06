# secure_client.py
import requests, os, argparse
from secure_utils import encrypt_file, decrypt_file, sha256_file

# Default config
SERVER_URL = "http://127.0.0.1:5002"
PASSWORD = "SuperSecret123!"
CLIENT_ID = "phone-B"
EXPECTED_SERVER_ID = "laptop-A"

def handshake(server_url):
    res = requests.post(f"{server_url}/handshake", json={
        "client_id": CLIENT_ID, "password": PASSWORD
    })
    data = res.json()
    if data.get("status") != "ok" or data.get("server_id") != EXPECTED_SERVER_ID:
        raise RuntimeError("Handshake failed or server mismatch")
    print("[+] Handshake successful")

def upload_file(server_url, filepath):
    if not os.path.exists(filepath):
        print(f"[!] File '{filepath}' not found. Creating it...")
        with open(filepath, "w") as f:
            f.write("Test file created automatically.\n")

    filename = os.path.basename(filepath)
    salt, nonce, ciphertext = encrypt_file(filepath, PASSWORD)
    sha_local = sha256_file(filepath)
    res = requests.post(f"{server_url}/upload_file", json={
        "client_id": CLIENT_ID,
        "password": PASSWORD,
        "filename": filename,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "sha256": sha_local
    })
    print(res.json())

def download_file(server_url, filename, save_as=None):
    save_as = save_as or filename
    res = requests.post(f"{server_url}/get_file", json={
        "client_id": CLIENT_ID,
        "password": PASSWORD,
        "filename": filename
    })
    data = res.json()
    if data.get("status") == "error":
        print("[-]", data.get("message"))
        return

    salt = bytes.fromhex(data["salt"])
    nonce = bytes.fromhex(data["nonce"])
    ciphertext = bytes.fromhex(data["ciphertext"])
    plaintext = decrypt_file(salt, nonce, ciphertext, PASSWORD)
    with open(save_as, "wb") as f:
        f.write(plaintext)
    print(f"[+] Downloaded and decrypted '{save_as}' (SHA256={data['sha256']})")

def main():
    parser = argparse.ArgumentParser(description="Secure P2P Client")
    parser.add_argument("--url", default=SERVER_URL, help="Server URL (default: http://127.0.0.1:5002)")
    sub = parser.add_subparsers(dest="command", required=True)

    up = sub.add_parser("upload", help="Upload a file to the server")
    up.add_argument("file", help="Path of the file to upload")

    down = sub.add_parser("download", help="Download a file from the server")
    down.add_argument("filename", help="Filename on the server")
    down.add_argument("--out", help="Save as name")

    args = parser.parse_args()

    handshake(args.url)

    if args.command == "upload":
        upload_file(args.url, args.file)
    elif args.command == "download":
        download_file(args.url, args.filename, args.out)

if __name__ == "__main__":
    main()
