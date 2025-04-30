from cryptography.fernet import Fernet
import os
import bcrypt

# Генерация ключа
def generate_key():
    return Fernet.generate_key()

# Сохранение ключа в файл
def save_key(key, filename='keys/secret.key'):  # поправил путь для безопасности
    os.makedirs(os.path.dirname(filename), exist_ok=True)  # создаём папку если нет
    with open(filename, 'wb') as f:
        f.write(key)

# Загрузка ключа
def load_key(filename='keys/secret.key'):
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

# НОВОЕ: Упрощенные функции для работы с otp_secret

def encrypt_data(data):
    key = load_key()
    return encrypt_message(data, key).decode()  # .decode(), чтобы сохранить как строку в БД

def decrypt_data(token):
    key = load_key()
    return decrypt_message(token.encode(), key)

# Проверка пароля при входе
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


