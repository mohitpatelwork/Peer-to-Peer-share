# secure_server.py
from flask import Flask, request, jsonify
import os
from secure_utils import encrypt_file, decrypt_file, sha256_file, sha256_bytes

app = Flask(__name__)

# Config — you can change if needed
PASSWORD = "SuperSecret123!"
SERVER_ID = "laptop-A"
ALLOWED_CLIENT_ID = "phone-B"
SHARE_DIR = "./shared"

@app.route("/handshake", methods=["POST"])
def handshake():
    data = request.get_json()
    if data.get("password") != PASSWORD or data.get("client_id") != ALLOWED_CLIENT_ID:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    return jsonify({"status": "ok", "server_id": SERVER_ID})

@app.route("/get_file", methods=["POST"])
def get_file():
    data = request.get_json()
    filename = data.get("filename")
    if data.get("password") != PASSWORD or data.get("client_id") != ALLOWED_CLIENT_ID:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    path = os.path.join(SHARE_DIR, filename)
    if not os.path.exists(path):
        return jsonify({"status": "error", "message": "File not found"}), 404

    from secure_utils import encrypt_file
    salt, nonce, ciphertext = encrypt_file(path, PASSWORD)
    return jsonify({
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "sha256": sha256_file(path)
    })

@app.route("/upload_file", methods=["POST"])
def upload_file():
    data = request.get_json()
    if data.get("password") != PASSWORD or data.get("client_id") != ALLOWED_CLIENT_ID:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    filename = data.get("filename")
    salt = bytes.fromhex(data["salt"])
    nonce = bytes.fromhex(data["nonce"])
    ciphertext = bytes.fromhex(data["ciphertext"])
    plaintext = decrypt_file(salt, nonce, ciphertext, PASSWORD)
    sha_local = sha256_bytes(plaintext)
    if sha_local != data["sha256"]:
        return jsonify({"status": "error", "message": "Integrity failed"}), 400

    os.makedirs(SHARE_DIR, exist_ok=True)
    with open(os.path.join(SHARE_DIR, filename), "wb") as f:
        f.write(plaintext)
    return jsonify({"status": "ok", "message": f"File '{filename}' uploaded successfully"})

def main():
    os.makedirs(SHARE_DIR, exist_ok=True)
    print(f"[*] Secure Flask Server running (1:1 mode) on port 5002")
    app.run(host="0.0.0.0", port=5002)

if __name__ == "__main__":
    main()
