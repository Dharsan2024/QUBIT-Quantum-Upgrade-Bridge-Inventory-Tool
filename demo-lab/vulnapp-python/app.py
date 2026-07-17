import hashlib
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import jwt

app = Flask(__name__)

# Dummy private key for JWT and encryption examples
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
PUBLIC_KEY = PRIVATE_KEY.public_key()


@app.route("/")
def index():
    return "QUBIT VulnApp (Python/Flask) running."


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    password = data.get("password", "")
    
    # QUBIT-FIXTURE: py-weakhash-01
    password_hash = hashlib.sha1(password.encode()).hexdigest()
    
    return jsonify({"status": "logged_in", "hash": password_hash})


@app.route("/token")
def token():
    # QUBIT-FIXTURE: py-ecdsa-sig-01 (using RSA here for simplicity, but simulating a vulnerable JWT pattern)
    encoded = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
    return jsonify({"token": encoded})


@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.json or {}
    message = data.get("message", "").encode()
    
    # QUBIT-FIXTURE: py-rsa-enc-01
    ciphertext = PUBLIC_KEY.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return jsonify({"ciphertext": ciphertext.hex()})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
