import os
from cryptography.fernet import Fernet, InvalidToken
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import getpass


def generate_key(master_password):
    """
    Генерирует ключ на основе мастер-пароля.

    :param master_password: Мастер-пароль, используемый для генерации ключа.
    :return: Сгенерированный ключ и соль.
    """
    salt = os.urandom(16)  # Создаем случайную соль
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key, salt


def load_key(master_password):
    """
    Загружает и восстанавливает ключ на основе мастер-пароля и сохраненной соли.

    :param master_password: Мастер-пароль, используемый для восстановления ключа.
    :return: Восстановленный ключ.
    """
    try:
        with open("key.key", "rb") as key_file:
            salt = key_file.read(16)  # Первые 16 байтов — это соль
            stored_key = key_file.read()  # Считываем оставшийся ключ
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Алгоритм хеширования
            length=32,
            salt=salt,  # Передаем соль
            iterations=100000,
            backend=default_backend()
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        if derived_key == stored_key:
            return derived_key
        else:
            raise ValueError("Неверный мастер-пароль")
    except FileNotFoundError:
        key, salt = generate_key(master_password)
        with open("key.key", "wb") as key_file:
            key_file.write(salt + key)
        return key


master_pwd = getpass.getpass(prompt="Введите мастер-пароль: ")
key = load_key(master_pwd)
fer = Fernet(key)


def view():
    try:
        with open('passwords.txt', 'r') as f:
            for line in f.readlines():
                data = line.rstrip()
                user, encrypted_password = data.split("|")
                try:
                    decrypted_password = fer.decrypt(encrypted_password.encode()).decode()
                    print(f"Пользователь: {user} | Пароль: {decrypted_password}")
                except InvalidToken:
                    print(f"Невозможно расшифровать пароль для пользователя {user}. Проверьте мастер-пароль.")
    except FileNotFoundError:
        print("Файл с паролями не найден.")


def add():
    account_name = input("Название аккаунта: ")
    pwd = getpass.getpass(prompt="Пароль: ")

    with open('passwords2.txt', 'a') as f:
        encrypted_pwd = fer.encrypt(pwd.encode()).decode()
        f.write(account_name + "|" + encrypted_pwd + "\n")
        print(f"Пароль для {account_name} добавлен.")


while True:
    mode = input("Добавить или просмотреть пароли? (view, add) Наберите 'q' для выхода: ").lower()
    if mode == 'q':
        break
    elif mode == 'view':
        view()
    elif mode == 'add':
        add()
    else:
        print("Неверный режим. Пожалуйста, выберите 'view', 'add' или 'q'.")