import json
import os
import pyotp
import qrcode
import bcrypt
from datetime import datetime
from utils.signature_utils import sign_message, verify_signature, generate_keys
import base64

USERS_FILE = 'data/users.json'

# Загрузка пользователей
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

# Сохранение пользователей
def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

# Хеширование пароля
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Проверка пароля
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Регистрация
def register_user(users):
    username = input("Придумай логин: ").strip()
    if username in users:
        print("Такой пользователь уже существует.")
        return

    password = input("Придумай пароль: ").strip()
    otp_secret = pyotp.random_base32()

    users[username] = {
        "password": hash_password(password),
        "otp_secret": otp_secret
    }

    save_users(users)

    uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="BankSecure")
    qrcode.make(uri).save(f"{username}_qr.png")

    print(f"✅ Пользователь {username} зарегистрирован.")
    print(f"QR-код для приложения Google Authenticator сохранён как {username}_qr.png")

# Вход
def login_user(users):
    username = input("Введите логин: ").strip()
    if username not in users:
        print("❌ Пользователь не найден.")
        return

    password = input("Введите пароль: ").strip()
    if not check_password(password, users[username]['password']):
        print("❌ Неверный пароль.")
        return

    totp = pyotp.TOTP(users[username]['otp_secret'])
    code = input("Введите 2FA код из приложения: ").strip()

    if totp.verify(code):
        print(f"✅ Добро пожаловать, {username}!")
        # Здесь можно вызвать функцию транзакции
        simulate_transaction(username)
    else:
        print("❌ Неверный 2FA код.")

# Симуляция безопасной транзакции
from utils.crypto_utils import encrypt_message, decrypt_message, load_key, save_key, generate_key

TRANSACTIONS_FILE = "data/transactions.log"
KEY_FILE = "keys/secret.key"

def simulate_transaction(username):
    print(f"\n💸 Создание транзакции для {username}")
    recipient = input("Кому перевести: ")
    amount = input("Сумма перевода: ")
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = f"[{time_now}] {username} перевёл {amount}₸ пользователю {recipient}"
    log_transaction(username, message)
    # Здесь можно позже добавить шифрование и сохранение транзакции

# Инициализация ключа
def get_encryption_key():
    if not os.path.exists(KEY_FILE):
        key = generate_key()
        save_key(key)
    else:
        key = load_key()
    return key

# Добавить транзакцию в журнал
if not os.path.exists("keys/private_key.pem") or not os.path.exists("keys/public_key.pem"):
    generate_keys()

def log_transaction(username, message):
    key = get_encryption_key()
    encrypted = encrypt_message(message, key)

    signature = sign_message(message)
    signature_b64 = base64.b64encode(signature).decode()

    # Сохраняем строку: зашифровано | подпись
    with open(TRANSACTIONS_FILE, "a", encoding="utf-8") as f:
        f.write(encrypted.decode() + "|" + signature_b64 + "\n")

    print("📩 Транзакция зашифрована, подписана и сохранена.")

# Просмотр журнала транзакций
def view_transactions():
    key = get_encryption_key()
    if not os.path.exists(TRANSACTIONS_FILE):
        print("Журнал пуст.")
        return

    with open(TRANSACTIONS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                enc_data, signature_b64 = line.strip().split("|")
                decrypted = decrypt_message(enc_data.encode(), key)
                signature = base64.b64decode(signature_b64)
                valid = verify_signature(decrypted, signature)
                status = "✅ Подпись верна" if valid else "❌ Подпись недействительна"
                print(f"{decrypted}\n{status}\n")
            except Exception as e:
                print("⚠️ Ошибка при расшифровке/проверке:", str(e))

# Главное меню
def main():
    users = load_users()
    while True:
        print("\n1. Зарегистрироваться")
        print("2. Войти")
        print("3. Выйти")
        print("4. Просмотреть журнал транзакций")
        choice = input("Выберите: ").strip()
        if choice == '1':
            register_user(users)
        elif choice == '2':
            login_user(users)
        elif choice == '3':
            print("До встречи!")
            break
        elif choice == '4':
            view_transactions()
        else:
            print("Неверный выбор.")

if __name__ == "__main__":
    main()




