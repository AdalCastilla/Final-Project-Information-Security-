
from flask import Flask, request, jsonify
from rsa_secure import encrypt, decrypt, sms_segments
from key_manager import load_public_key, load_private_key

import time
import secrets
import hmac


app = Flask(__name__)

# Laboratory access tokens
TOKENS = {
    "alice": secrets.token_urlsafe(24),
    "bob": secrets.token_urlsafe(24)
}


# User authentication
def authenticate(user):

    token = request.headers.get("X-Access-Token", "")

    return (
        user in TOKENS
        and hmac.compare_digest(token, TOKENS[user])
    )


# Server Status
@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "application": "RSA Secure SMS",
        "status": "Online",
        "algorithm": "RSA-OAEP",
        "hash": "SHA-256",
        "encoding": "Base64"
    })


# RSA Encryption Endpoint
@app.route("/encrypt", methods=["POST"])
def encrypt_message():

    data = request.get_json(silent=True) or {}

    sender = data.get("sender", "")
    receiver = data.get("receiver", "")
    message = data.get("message", "")

    if not authenticate(sender):
        return jsonify({"error": "Unauthorized"}), 401

    if receiver not in TOKENS or receiver == sender:
        return jsonify({"error": "Invalid receiver"}), 400

    if not isinstance(message, str) or not message:
        return jsonify({"error": "Empty or invalid message"}), 400

    try:

        public_key = load_public_key(receiver)

        max_bytes = public_key.size_in_bytes() - 66

        if len(message.encode("utf-8")) > max_bytes:
            return jsonify({
                "error": "Message too large",
                "maximum_bytes": max_bytes
            }), 400

        start = time.perf_counter()

        ciphertext = encrypt(message, public_key)

        elapsed = (time.perf_counter() - start) * 1000

        return jsonify({
            "status": "success",
            "sender": sender,
            "receiver": receiver,
            "ciphertext": ciphertext,
            "key_size": public_key.size_in_bits(),
            "base64_characters": len(ciphertext),
            "sms_segments": sms_segments(ciphertext),
            "encryption_time_ms": round(elapsed, 4)
        })

    except ValueError:

        return jsonify({
            "error": "Encryption failed"
        }), 400


# RSA Decryption Endpoint
@app.route("/decrypt", methods=["POST"])
def decrypt_message():

    data = request.get_json(silent=True) or {}

    receiver = data.get("receiver", "")
    ciphertext = data.get("ciphertext", "")

    if not authenticate(receiver):
        return jsonify({"error": "Unauthorized"}), 401

    if not isinstance(ciphertext, str) or not ciphertext:
        return jsonify({
            "error": "Empty or invalid ciphertext"
        }), 400

    try:

        private_key = load_private_key(receiver)

        start = time.perf_counter()

        message = decrypt(ciphertext, private_key)

        elapsed = (time.perf_counter() - start) * 1000

        return jsonify({
            "status": "success",
            "receiver": receiver,
            "message": message,
            "decryption_time_ms": round(elapsed, 4)
        })

    except ValueError:

        return jsonify({
            "error": "Decryption denied"
        }), 400


# Start Server
if __name__ == "__main__":

    print("==============================")
    print("   RSA SECURE SMS SERVER")
    print("==============================")

    print("Alice access token:", TOKENS["alice"])
    print("Bob access token:", TOKENS["bob"])

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
