
# 🏦 BankOTP — Secure Electronic Payment System with Two-Factor Authentication

**BankOTP** — is a secure web application that simulates an electronic banking platform with a strong emphasis on cryptography and two-factor authentication (2FA). It ensures secure user interactions by integrating AES encryption, RSA digital signatures, bcrypt password hashing, and Google reCAPTCHA.

---

## ⚙️ Features

- User registration and login with strong bcrypt password hashing
- Two-factor authentication using OTP (TOTP-based)
- Google reCAPTCHA (v2) integration to prevent bots and abuse
- AES encryption for secure storage of OTP secrets in PostgreSQL
- Digital signature generation and verification using RSA
- Transaction system with history tracking and logging
- PostgreSQL database for storing users and transactions
- QR code generation for OTP setup
- Secure session management with Flask

---

## 🔒 Security and Cryptography

- **bcrypt** — secure password hashing with salt to protect against brute-force attacks  
- **AES** — symmetric encryption for securely storing OTP secrets  
- **RSA** — digital signatures to verify the authenticity of transactions  
- **TOTP (Time-based One-Time Passwords)** — implemented using PyOTP for two-factor authentication  
- **Google reCAPTCHA** — protects against automated bots and abuse  
- **Logging** — all sensitive actions are recorded in the `transactions.log` file for audit purposes  
- **PostgreSQL** — used as a robust and secure relational database for storing all user and transaction data

---


## 📁 Project Structure

```
BankOTP/
├── app.py                  # Main Flask application logic + PostgreSQL database
├── main.py                 # Entry point to start the app
├── templates/              # HTML templates
├── static/                 # CSS and assets
├── utils/
│   ├── crypto_utils.py     # AES encryption
    └── signature_utils.py  # RSA signatures
│   └── helpers.py          # Helper functions (e.g., normalization, validation)
├── secret.key              # AES encryption key for OTP
├── private_key.pem         # RSA private key for digital signatures
├── public_key.pem          # RSA public key for signature verification
├── transactions.log        # Transaction operation logs
└── README.md               # Project description and documentation
```

---

## 🛠 Installation & Setup

```bash
git clone https://github.com/your_username/BankOTP.git
cd BankOTP
python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

---

## 🔐 Google reCAPTCHA Setup

1. Go to [Google reCAPTCHA](https://www.google.com/recaptcha/admin/create)
2. Choose reCAPTCHA v2 ("I'm not a robot") and generate keys
3. Insert the **site key** in `login.html` and `register.html`:

```html
<div class="g-recaptcha" data-sitekey="YOUR_SITE_KEY"></div>
```

4. Add the **secret key** to `app.py`:

```python
RECAPTCHA_SECRET_KEY = 'YOUR_SECRET_KEY'
```

---

## 🔒 Security Practices

- 🔑 Bcrypt Password Hashing
- Passwords are hashed using the bcrypt algorithm, which provides strong protection against brute-force attacks and rainbow tables due to its adaptive nature and built-in salt generation.
- 🔐 AES Encryption for OTP Secrets
- User-specific OTP secrets are encrypted using AES (symmetric encryption) before being stored in the PostgreSQL database. This ensures the secrets cannot be read even if the database is compromised.
- Google reCAPTCHA prevents automated form submissions
- Transactions and logins are logged for traceability
- 🔐 RSA Digital Signatures
- Transactions are digitally signed using RSA private keys and verified using public keys. This guarantees the authenticity and integrity of signed messages or transactions.

---

## 📚 Technologies Used

- Python 3 + Flask
- PostgreSQL
- PyOTP for TOTP OTP generation
- Cryptography library for AES & RSA
- Bcrypt for password hashing
- qrcode for OTP setup
- HTML/CSS (Bootstrap) for UI 
- Google reCAPTCHA API
- JavaScript

---

## 📜 Project Goals

**Goal:** To create a secure, user-friendly demo of an electronic payment system using modern cryptographic tools and strong two-factor authentication practices.

**Tasks:**
- Implement user identity verification with bcrypt and OTP
- Encrypt and securely store sensitive data (like OTP secrets)
- Digitally sign transactions to ensure data authenticity
- Prevent unauthorized access using CAPTCHA and secure sessions
- Log and trace all financial operations

---

## 📌 Compliance Context

The project is inspired by industry security standards like **PCI DSS**, which sets requirements for securely handling and storing payment data. Key principles include:
- Strong access control and authentication
- Encrypted transmission and storage of sensitive data
- Regular monitoring and testing

---

## 📘 Educational Context

This application was developed as part of a diploma thesis:

**"Using Cryptography in Electronic Payment Systems Based on Two-Factor Authentication"**

It showcases the integration of modern cryptographic techniques into a banking system simulation, and can be used both for educational and demonstrative purposes.

---

## 👨‍💻 Author

> Developed as a bachelor's graduation project by a student specializing in Cybersecurity at the Faculty of IT.

---

## 📜 License

This project is for educational purposes only. For production use, a full security audit and redesign is strongly recommended.
