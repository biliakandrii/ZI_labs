# rsa_crypto.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os
import time


class RSACrypto:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self, key_size=2048):
        """Генерує пару ключів RSA"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()

    def save_keys(self, private_key_path, public_key_path):
        """Зберігає ключі у файли"""
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)

    def load_keys(self, private_key_path, public_key_path):
        """Завантажує ключі з файлів"""
        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read()
            )

    def encrypt_file(self, input_path, output_path):
        """Шифрує файл"""
        chunk_size = 190  # Максимальний розмір блоку для RSA-2048

        with open(input_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if not chunk:
                    break

                encrypted = self.public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                out_file.write(len(encrypted).to_bytes(4, byteorder='big'))
                out_file.write(encrypted)

    def decrypt_file(self, input_path, output_path):
        """Розшифровує файл"""
        with open(input_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
            while True:
                size_bytes = in_file.read(4)
                if not size_bytes:
                    break

                chunk_size = int.from_bytes(size_bytes, byteorder='big')
                encrypted_chunk = in_file.read(chunk_size)

                decrypted = self.private_key.decrypt(
                    encrypted_chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                out_file.write(decrypted)

    def measure_performance(self, file_size_mb=1):
        """Вимірює швидкість шифрування та розшифрування"""
        test_file = "test_data.bin"
        encrypted_file = "encrypted.bin"
        decrypted_file = "decrypted.bin"

        with open(test_file, 'wb') as f:
            f.write(os.urandom(file_size_mb * 1024 * 1024))

        start_time = time.time()
        self.encrypt_file(test_file, encrypted_file)
        encryption_time = time.time() - start_time

        start_time = time.time()
        self.decrypt_file(encrypted_file, decrypted_file)
        decryption_time = time.time() - start_time

        os.remove(test_file)
        os.remove(encrypted_file)
        os.remove(decrypted_file)

        return encryption_time, decryption_time

