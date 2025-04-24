from flask import Flask, render_template, request, redirect, session, url_for, flash
import json
import pyotp
import hashlib
import qrcode
import base64
import os
from datetime import datetime
from io import BytesIO
import requests

RECAPTCHA_SECRET_KEY = "6LdiYh8rAAAAAE-tFV03ixrEC2Ea9byt67X6Yq2A"

app = Flask(__name__)
app.secret_key = 'your_flask_secret_key'

USERS_FILE = 'data/users.json'
TX_FILE = 'data/transactions.json'

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        users = json.load(f)
        for user in users.values():
            if 'balance' not in user:
                user['balance'] = 0
        return users

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_transactions():
    if not os.path.exists(TX_FILE):
        return []
    with open(TX_FILE, 'r') as f:
        return json.load(f)

def save_transactions(transactions):
    with open(TX_FILE, 'w') as f:
        json.dump(transactions, f, indent=4)

# Загрузка отзывов
def load_reviews():
    if not os.path.exists("data/reviews.json"):
        return []
    with open("data/reviews.json", "r", encoding="utf-8") as f:
        return json.load(f)

# Сохранение отзывов
def save_review(name, message):
    reviews = load_reviews()
    reviews.append({"name": name, "message": message})
    with open("data/reviews.json", "w", encoding="utf-8") as f:
        json.dump(reviews, f, ensure_ascii=False, indent=4)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        data = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        response = requests.post(verify_url, data=data)
        result = response.json()

        if not result.get('success'):
            error = "Пожалуйста, подтвердите, что вы не робот!"
            return render_template('register.html', error=error)

        users = load_users()
        username = request.form['username']
        password = request.form['password']

        if username in users:
            error = "Пользователь с таким именем уже существует!"
            return render_template('register.html', error=error)

        secret_key = pyotp.random_base32()
        users[username] = {
            'password': hash_password(password),
            'otp_secret': secret_key,
            'balance': 100000
        }
        save_users(users)

        uri = pyotp.TOTP(secret_key).provisioning_uri(name=username, issuer_name="BankOTP")

        qr = qrcode.make(uri)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

        return render_template("register_success.html", username=username, qr_code=qr_code_base64, otp_uri=uri)

    return render_template('register.html')

@app.route('/about')
def about():
    reviews = load_reviews()
    return render_template('about.html', reviews=reviews)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Проверка reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        payload = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        recaptcha_result = requests.post(verify_url, data=payload).json()

        if not recaptcha_result.get('success'):
            error = 'Проверка reCAPTCHA не пройдена!'
            return render_template('login.html', error=error)

        # Проверка пользователя
        users = load_users()
        username = request.form['username']
        password = request.form['password']

        user = users.get(username)
        if not user:
            error = "Пользователь не найден!"
        elif user['password'] != hash_password(password):
            error = "Неверный пароль!"
        else:
            session['username'] = username
            return redirect('/verify-otp')

    return render_template('login.html', error=error)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'username' not in session:
        return redirect('/login')

    username = session['username']
    users = load_users()
    otp_secret = users[username]['otp_secret']
    totp = pyotp.TOTP(otp_secret)
    error = None

    if request.method == 'POST':
        otp = request.form['otp']
        if totp.verify(otp):
            session['authenticated'] = True
            return redirect(url_for('account'))
        else:
            error = "Неверный OTP-код!"

    return render_template('verify_otp.html', error=error)

@app.route('/submit_review', methods=['POST'])
def submit_review():
    name = request.form.get("name")
    message = request.form.get("message")
    if name and message:
        save_review(name, message)
    return redirect(url_for('about'))

@app.route('/account')
def account():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    # Получаем баланс и другую инфу
    with open('data/users.json', 'r') as f:
        data = json.load(f)
        balance = data.get(username, {}).get('balance', 0)

    return render_template('account.html', username=username, balance=balance)

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect('/login')

    users = load_users()
    username = session['username']
    balance = users[username].get('balance', 0)

    return render_template('dashboard.html', username=username, balance=balance)

@app.route('/transfer', methods=['POST'])
def transfer():
    if not session.get('authenticated'):
        return redirect('/login')

    users = load_users()
    transactions = load_transactions()
    sender = session['username']
    recipient = request.form['recipient']
    amount = float(request.form['amount'])
    otp = request.form['otp']

    # Проверка OTP
    totp = pyotp.TOTP(users[sender]['otp_secret'])
    if not totp.verify(otp):
        return render_template('dashboard.html',
                               username=sender,
                               balance=users[sender]['balance'],
                               error='Неверный OTP-код!')

    if recipient not in users:
        return render_template('dashboard.html',
                               username=sender,
                               balance=users[sender]['balance'],
                               error='Получатель не найден!')

    if users[sender]['balance'] < amount:
        return render_template('dashboard.html',
                               username=sender,
                               balance=users[sender]['balance'],
                               error='Недостаточно средств!')

    users[sender]['balance'] -= amount
    users[recipient]['balance'] += amount
    save_users(users)

    transactions.append({
        'sender': sender,
        'recipient': recipient,
        'amount': amount,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    save_transactions(transactions)

    return redirect('/dashboard')


@app.route('/transactions')
def transactions():
    if not session.get('authenticated'):
        return redirect('/login')

    username = session['username']
    all_tx = load_transactions()
    user_tx = [tx for tx in all_tx if tx['sender'] == username or tx['recipient'] == username]

    return render_template('transactions.html', username=username, transactions=user_tx)

if __name__ == '__main__':
    app.run(debug=True)
