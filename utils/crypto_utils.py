from cryptography.fernet import Fernet

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
