import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.backends import default_backend
import base64

# --- Функция: Подписание XML ---
def sign_xml(xml_file_path, private_key_path, signature_output_path):
    # Чтение XML файла
    with open(xml_file_path, 'rb') as f:
        xml_data = f.read()

    # Вычисление хэша
    digest = hashlib.sha256(xml_data).digest()
    timestamp = datetime.now().isoformat()

    # Загрузка закрытого ключа
    with open(private_key_path, 'rb') as f:
        private_key = load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Подпись хэша
    signature = private_key.sign(
        digest,
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256())
    )

    # Сохранение подписи, хэша и времени
    with open(signature_output_path, 'w') as f:
        f.write(f"timestamp={timestamp}\n")
        f.write(f"hash={base64.b64encode(digest).decode()}\n")
        f.write(f"signature={base64.b64encode(signature).decode()}\n")

    print("✅ Документ успешно подписан.")
    return digest, signature, timestamp

# --- Функция: Проверка подписи ---
def verify_xml(xml_file_path, signature_file_path, public_key_path):
    # Чтение XML
    with open(xml_file_path, 'rb') as f:
        xml_data = f.read()

    # Вычисление текущего хэша
    current_hash = hashlib.sha256(xml_data).digest()

    # Чтение подписи
    data = {}
    with open(signature_file_path, 'r') as f:
        for line in f:
            key, value = line.strip().split('=', 1)
            data[key] = value

    stored_hash = base64.b64decode(data['hash'])
    stored_signature = base64.b64decode(data['signature'])
    timestamp = data['timestamp']

    # Проверка совпадения хэшей
    if current_hash != stored_hash:
        print("❌ Хэши не совпадают — документ был изменён.")
        return False

    # Загрузка открытого ключа
    with open(public_key_path, 'rb') as f:
        public_key = load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    # Проверка подписи
    try:
        public_key.verify(
            stored_signature,
            stored_hash,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())
        )
        print(f"✅ Подпись действительна. Время подписи: {timestamp}")
        return True
    except Exception as e:
        print(f"❌ Неверная подпись: {e}")
        return False

# --- Генерация пары ключей RSA (если нет) ---
def generate_rsa_keys(private_key_path='private_key.pem', public_key_path='public_key.pem'):
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Сохранение закрытого ключа
    with open(private_key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))

    # Сохранение открытого ключа
    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ))

    print("🔑 Ключи успешно сгенерированы.")

# --- Точка входа ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Подпись и проверка XML документов.")
    subparsers = parser.add_subparsers(dest='command')

    # Подкоманда: sign
    sign_parser = subparsers.add_parser('sign', help='Подписать XML')
    sign_parser.add_argument('--xml', required=True, help='Путь к XML файлу')
    sign_parser.add_argument('--key', required=True, help='Путь к закрытому ключу')
    sign_parser.add_argument('--output', required=True, help='Файл для сохранения подписи')

    # Подкоманда: verify
    verify_parser = subparsers.add_parser('verify', help='Проверить подпись')
    verify_parser.add_argument('--xml', required=True, help='Путь к XML файлу')
    verify_parser.add_argument('--sig', required=True, help='Путь к файлу подписи')
    verify_parser.add_argument('--key', required=True, help='Путь к открытому ключу')

    # Подкоманда: generate-keys
    gen_parser = subparsers.add_parser('generate-keys', help='Сгенерировать ключи')

    args = parser.parse_args()

    if args.command == 'sign':
        sign_xml(args.xml, args.key, args.output)
    elif args.command == 'verify':
        verify_xml(args.xml, args.sig, args.key)
    elif args.command == 'generate-keys':
        generate_rsa_keys()
    else:
        parser.print_help()
