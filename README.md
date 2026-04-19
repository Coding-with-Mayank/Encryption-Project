# Encryption-Project

# QR-Code Based Secure Data Sharing
### A locally-running Python web application

---

## Project Overview

This application provides a secure, convenient method for transmitting sensitive
information using **AES-256 encryption** and **QR code technology**.

Data is encrypted before being embedded in a QR code. On the receiving end, the
QR code is scanned, the payload pasted, and decrypted using the same secret key.
A **SHA-256 hash** verifies message integrity throughout.

---

## Tech Stack

| Layer      | Technology                          |
|------------|-------------------------------------|
| Backend    | Python 3.8+ · Flask                 |
| Encryption | `cryptography` — AES-256-CBC, PBKDF2|
| Integrity  | SHA-256 (hashlib)                   |
| QR Code    | `qrcode[pil]` + Pillow              |
| Frontend   | HTML · CSS · Vanilla JS             |

---

## Setup & Run

### 1. Clone / download the project
```
secure_qr_app/
├── app.py
├── requirements.txt
├── README.md
└── templates/
    └── index.html
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the app
```bash
python app.py
```

### 4. Open in browser
```
http://localhost:5000
```

---

## How It Works

### Encryption Flow
```
Plaintext
    │
    ├─► SHA-256 hash  ──────────────────────────► stored in payload
    │
    ├─► Random salt (16 bytes)
    │       │
    │       └─► PBKDF2-HMAC-SHA256 (200,000 iter) ─► 256-bit AES key
    │
    ├─► Random IV (16 bytes)
    │
    └─► AES-256-CBC + PKCS7 padding ─► Ciphertext
                                            │
                              Base64 encode all parts
                                            │
                                     JSON payload
                                            │
                                        QR Code
```

### Decryption Flow
```
QR Code ─► JSON payload ─► Base64 decode
                                │
                     PBKDF2(password, salt) ─► AES key
                                │
                     AES-256-CBC decrypt + unpad
                                │
                          Plaintext
                                │
                     SHA-256(plaintext) == stored hash?
                          ✓ Verified    ✗ Tampered
```

---

## API Endpoints

| Method | Route              | Description                     |
|--------|--------------------|---------------------------------|
| GET    | `/`                | Serve the web UI                |
| POST   | `/api/encrypt`     | Encrypt message, return QR      |
| POST   | `/api/decrypt`     | Decrypt payload, verify hash    |
| POST   | `/api/download-qr` | Download QR code as PNG         |

---

## Security Details

- **AES-256-CBC** with random IV — same message + key yields different ciphertext each time
- **PKCS7 padding** ensures plaintext fits AES block boundaries
- **PBKDF2-HMAC-SHA256** with 200,000 iterations resists brute-force attacks on the password
- **Random 16-byte salt** per encryption prevents rainbow table attacks
- **SHA-256 hash** of the original plaintext detects tampering after transmission

---

## Important Security Note

> Never transmit the secret key through the same channel as the QR code.
> Share keys verbally or via a separate, trusted, encrypted medium.
