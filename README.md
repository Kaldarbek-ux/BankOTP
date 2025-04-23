
# 🏦 BankOTP — Electronic Payment System with Two-Factor Authentication

**BankOTP** is a demo web application implementing a secure electronic payment system using passwords and one-time passwords (OTP) as part of a two-factor authentication (2FA) process. The project utilizes cryptography, Google reCAPTCHA, transaction logging, and OTP mechanisms.

---

## ⚙️ Features

- User registration and login
- Login verification with OTP (two-factor authentication)
- Google reCAPTCHA (v2) for spam/bot protection
- View transaction history
- Transfer funds between users
- Secure password hashing and verification
- Digital signatures support (RSA-based)
- QR code generation for OTP scanning
- Logging of all transaction operations

---

## 📁 Project Structure

```
BankOTP/
├── app.py               # Flask app logic
├── main.py              # Entry point
├── templates/           # HTML templates
├── static/              # CSS styles
├── utils/               # Cryptography and helper utilities
├── users.json           # User database (JSON)
├── transactions.json    # Transactions database
├── transactions.log     # Logging file
├── private_key.pem      # RSA private key
├── public_key.pem       # RSA public key
├── secret.key           # OTP encryption key
└── README.md            # Project description
```

---

## 🛠 Installation & Setup

```bash
git clone https://github.com/your_username/BankOTP.git
cd BankOTP
python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
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

- Passwords are hashed with SHA-256 (or better)
- OTP is time-based (TOTP using PyOTP)
- Google reCAPTCHA prevents automated form submissions
- Transactions and logins are logged for traceability

---

## 📚 Technologies Used

- Python 3 + Flask
- HTML + Bootstrap
- PyOTP, qrcode
- Google reCAPTCHA API
- JSON storage
- RSA & SHA256 (cryptography)

---

## 👨‍🎓 Author

> This project was developed as part of a diploma thesis:  
> **"Using Cryptography in Electronic Payment Systems Based on Two-Factor Authentication"**

---

## 📜 License

This project is for educational purposes only. For production use, a full security audit and redesign is strongly recommended.
