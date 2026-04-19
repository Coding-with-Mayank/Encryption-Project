"""
QR-Code Based Secure Data Sharing — Flask Backend
==================================================
Run:
    pip install flask cryptography qrcode[pil] Pillow
    python app.py
Then open: http://localhost:5000
"""

import os
import io
import base64
import hashlib
import json

from flask import Flask, render_template, request, jsonify, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import qrcode
from qrcode.image.pil import PilImage
from PIL import Image

app = Flask(__name__)

BACKEND        = default_backend()
KDF_SALT_SIZE  = 16
AES_KEY_SIZE   = 32
AES_IV_SIZE    = 16
KDF_ITERATIONS = 200_000


# ── Crypto helpers ────────────────────────────────────────────────────────────

def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=BACKEND,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: str, password: str) -> dict:
    salt      = os.urandom(KDF_SALT_SIZE)
    iv        = os.urandom(AES_IV_SIZE)
    key       = derive_key(password, salt)
    padder    = padding.PKCS7(128).padder()
    padded    = padder.update(plaintext.encode()) + padder.finalize()
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    enc       = cipher.encryptor()
    ct        = enc.update(padded) + enc.finalize()
    return {
        "salt": base64.b64encode(salt).decode(),
        "iv":   base64.b64encode(iv).decode(),
        "ct":   base64.b64encode(ct).decode(),
        "hash": sha256_hash(plaintext),
    }


def decrypt(payload: dict, password: str) -> str:
    salt      = base64.b64decode(payload["salt"])
    iv        = base64.b64decode(payload["iv"])
    ct        = base64.b64decode(payload["ct"])
    key       = derive_key(password, salt)
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=BACKEND)
    dec       = cipher.decryptor()
    padded    = dec.update(ct) + dec.finalize()
    unpadder  = padding.PKCS7(128).unpadder()
    plaintext = (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")
    if sha256_hash(plaintext) != payload["hash"]:
        raise ValueError("Integrity check failed — SHA-256 mismatch.")
    return plaintext


def make_qr_png(data: str, color: str = "#0a2e26") -> bytes:
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color=color, back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data     = request.get_json()
    message  = (data.get("message") or "").strip()
    password = (data.get("password") or "").strip()

    if not message:
        return jsonify(error="Message cannot be empty."), 400
    if not password or len(password) < 6:
        return jsonify(error="Key must be at least 6 characters."), 400

    payload    = encrypt(message, password)
    json_str   = json.dumps(payload, separators=(",", ":"))
    qr_bytes   = make_qr_png(json_str)
    qr_b64     = base64.b64encode(qr_bytes).decode()

    return jsonify(
        payload  = payload,
        qr_image = f"data:image/png;base64,{qr_b64}",
        hash     = payload["hash"],
    )


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data     = request.get_json()
    raw      = (data.get("payload") or "").strip()
    password = (data.get("password") or "").strip()

    if not raw or not password:
        return jsonify(error="Payload and key are required."), 400

    try:
        payload   = json.loads(raw)
        plaintext = decrypt(payload, password)
        return jsonify(message=plaintext, hash=payload.get("hash", ""))
    except (json.JSONDecodeError, KeyError):
        return jsonify(error="Invalid payload format."), 400
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception:
        return jsonify(error="Decryption failed — wrong key or corrupted data."), 400


@app.route("/api/download-qr", methods=["POST"])
def api_download_qr():
    data     = request.get_json()
    raw      = (data.get("payload") or "").strip()
    if not raw:
        return jsonify(error="No payload."), 400
    qr_bytes = make_qr_png(raw)
    return send_file(
        io.BytesIO(qr_bytes),
        mimetype="image/png",
        as_attachment=True,
        download_name="secure_qr.png",
    )


if __name__ == "__main__":
    print("\n  Secure QR App running at → http://localhost:5000\n")
    app.run(debug=True, port=5000)
