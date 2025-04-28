from flask import Flask, render_template, request, redirect, session, url_for, flash
import json
import pyotp
import qrcode
import base64
import bcrypt
import os
import re
import psycopg2
from datetime import datetime
from decimal import Decimal
from cryptography.fernet import Fernet
from utils.signature_utils import sign_message, verify_signature
from utils.crypto_utils import encrypt_data, decrypt_data
from utils.crypto_utils import check_password
from io import BytesIO
import requests

RECAPTCHA_SECRET_KEY = "6LdiYh8rAAAAAE-tFV03ixrEC2Ea9byt67X6Yq2A"

app = Flask(__name__)
app.secret_key = 'your_flask_secret_key'

USERS_FILE = 'data/users.json'
TX_FILE = 'data/transactions.json'

def get_db_connection():
    conn = psycopg2.connect(
        host='localhost',
        database='BankOTP',
        user='postgres',
        password='Nurik2004'
    )
    return conn

def get_user_by_username(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username, password, phone, otp_secret, balance FROM users WHERE username = %s', (username,))
    user = cur.fetchone()
    conn.close()
    if user:
        otp_secret_encrypted = user[3]
        decrypted_otp = None
        if otp_secret_encrypted:  # <- Проверка: если otp_secret есть
            try:
                decrypted_otp = decrypt_data(otp_secret_encrypted)
            except Exception as e:
                print(f"Ошибка при расшифровке OTP: {e}")
                decrypted_otp = None  # или можно выбросить ошибку
        return {
            'username': user[0],
            'password': user[1],
            'phone': user[2],
            'otp_secret': decrypted_otp,
            'balance': user[4]
        }
    return None


def get_user_by_phone(phone):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username, password, phone FROM users WHERE phone = %s', (phone,))
    user = cur.fetchone()
    conn.close()
    if user:
        return {'username': user[0], 'password': user[1], 'phone': user[2]}
    return None

def update_user_balance(username, new_balance):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'UPDATE users SET balance = %s WHERE username = %s',
        (new_balance, username)
    )
    conn.commit()
    conn.close()


def create_user(username, password, phone, otp_secret):
    encrypted_otp = encrypt_data(otp_secret)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO users (username, password, phone, otp_secret, balance) VALUES (%s, %s, %s, %s, %s)',
        (username, password, phone, encrypted_otp, 100000)
    )
    conn.commit()
    conn.close()

# Хеширование пароля с использованием bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()  # Сохраняем в базе как строку

def encrypt_existing_otp_secrets():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT username, otp_secret FROM users')
    users = cur.fetchall()
    for username, otp_secret in users:
        encrypted_otp = encrypt_data(otp_secret)
        cur.execute('UPDATE users SET otp_secret = %s WHERE username = %s', (encrypted_otp, username))
    conn.commit()
    conn.close()

def normalize_phone(phone):
    """Удаляет все символы, кроме цифр и знака + в начале."""
    phone = phone.strip()
    # Оставляем только + и цифры
    normalized = '+' + re.sub(r'\D', '', phone)
    if not normalized.startswith('+'):
        normalized = '+' + normalized.lstrip('+')
    return normalized

def load_transactions():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT id, sender, recipient, amount, timestamp FROM transactions ORDER BY timestamp DESC')
    transactions = cur.fetchall()
    conn.close()

    # Формируем список транзакций в нужном формате
    return [
        {
            'id': tx[0],
            'sender': tx[1],
            'recipient': tx[2],
            'amount': tx[3],
            'timestamp': tx[4]
        }
        for tx in transactions
    ]

def save_transaction(sender, recipient, amount):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO transactions (sender, recipient, amount, timestamp) VALUES (%s, %s, %s, %s)',
        (sender, recipient, amount, datetime.now())
    )
    conn.commit()
    conn.close()

# Генерация ключа
def generate_key():
    return Fernet.generate_key()

# Сохранение ключа в файл
def save_key(key, filename='secret.key'):
    with open(filename, 'wb') as f:
        f.write(key)

# Загрузка ключа
def load_key(filename='secret.key'):
    with open(filename, 'rb') as f:
        return f.read()

# Шифрование сообщения
def encrypt_message(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())

# Расшифровка сообщения
def decrypt_message(token, key):
    f = Fernet(key)
    return f.decrypt(token).decode()

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

def log_transaction(sender, recipient, amount):
    message = f"Transfer from {sender} to {recipient} of {amount} units"
    # Подписываем сообщение
    signature = sign_message(message)

    # Сохраняем зашифрованное сообщение и подпись
    encrypted_message = encrypt_message(message, key)
    with open("transactions.log", "a") as f:
        f.write(f"{encrypted_message.decode()}|{base64.b64encode(signature).decode()}\n")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        # Проверка reCAPTCHA
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

        username = request.form['username'].strip()
        phone = request.form['phone'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Проверка существования пользователя по username
        existing_user = get_user_by_username(username)
        if existing_user:
            error = "Пользователь с таким именем уже существует!"
            return render_template('register.html', error=error)

        # Проверка существования пользователя по номеру телефона
        if get_user_by_phone(phone):
            error = "Пользователь с таким номером телефона уже существует!"
            return render_template('register.html', error=error)

        if password != confirm_password:
            error = "Пароли не совпадают."
            return render_template('register.html', error=error)

        # Генерация OTP секрета
        secret_key = pyotp.random_base32()

        # Создание пользователя в базе
        create_user(username, hash_password(password), phone, secret_key)

        # Генерация QR-кода для 2FA
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

        identifier = request.form['username'].strip()
        password = request.form['password']

        # Поиск пользователя
        user = get_user_by_username(identifier)
        if not user:
            normalized_identifier = normalize_phone(identifier)
            user = get_user_by_phone(normalized_identifier)

        if not user:
            error = "Пользователь не найден!"
        elif not check_password(password, user['password']):
            error = "Неверный пароль!"
        else:
            # Авторизация успешна
            session['username'] = user['username']
            return redirect('/verify-otp')

    return render_template('login.html', error=error)


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'username' not in session:
        return redirect('/login')

    username = session['username']
    user = get_user_by_username(username)

    if not user:
        return redirect('/login')

    otp_secret = user['otp_secret']
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

    # Получаем информацию о пользователе из базы данных
    user = get_user_by_username(username)

    if user:
        balance = user['balance']
    else:
        balance = 0  # Если пользователя не нашли, то баланс 0

    return render_template('account.html', username=username, balance=balance)


@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect('/login')

    username = session['username']
    user = get_user_by_username(username)

    if not user:
        return redirect('/login')

    balance = user.get('balance', 0)

    return render_template('dashboard.html', username=username, balance=balance)


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'username' not in session:
        return redirect('/login')

    error = None
    if request.method == 'POST':
        sender_username = session['username']
        recipient_username = request.form['recipient'].strip()
        amount = Decimal(request.form['amount'])

        # Проверка существования получателя
        recipient = get_user_by_username(recipient_username)
        if not recipient:
            error = 'Получатель не найден!'
            return render_template('dashboard.html', error=error)

        # Получение данных отправителя
        sender = get_user_by_username(sender_username)
        if sender['balance'] < amount:
            error = 'Недостаточно средств на балансе!'
            return render_template('dashboard.html', error=error)

        # Обновляем балансы
        update_user_balance(sender_username, sender['balance'] - amount)
        update_user_balance(recipient_username, recipient['balance'] + amount)

        # Генерируем временную метку перевода
        timestamp = datetime.now()

        # Формируем сообщение для подписи
        message = f"{sender_username}:{recipient_username}:{amount}:{timestamp}"

        # Создаём цифровую подпись
        signature = sign_message(message)

        # Сохраняем транзакцию в БД вместе с подписью
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO transactions (sender, recipient, amount, timestamp, signature) VALUES (%s, %s, %s, %s, %s)',
            (sender_username, recipient_username, amount, timestamp, signature)
        )
        conn.commit()
        conn.close()

        return redirect('/transactions')  # Перенаправляем на страницу истории транзакций

    return render_template('dashboard.html', error=error)


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