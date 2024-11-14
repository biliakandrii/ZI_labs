# test_rsa_crypto.py
import unittest
import os
import tempfile
from rsa_crypto import RSACrypto


class TestRSACrypto(unittest.TestCase):
    def setUp(self):
        self.rsa_crypto = RSACrypto()
        self.rsa_crypto.generate_keys()
        self.test_dir = tempfile.mkdtemp()

    def test_key_generation(self):
        """Тестує генерацію ключів"""
        self.assertIsNotNone(self.rsa_crypto.private_key)
        self.assertIsNotNone(self.rsa_crypto.public_key)

    def test_key_save_load(self):
        """Тестує збереження та завантаження ключів"""
        private_key_path = os.path.join(self.test_dir, 'private.pem')
        public_key_path = os.path.join(self.test_dir, 'public.pem')

        self.rsa_crypto.save_keys(private_key_path, public_key_path)

        self.assertTrue(os.path.exists(private_key_path))
        self.assertTrue(os.path.exists(public_key_path))

        new_rsa = RSACrypto()
        new_rsa.load_keys(private_key_path, public_key_path)

        self.assertIsNotNone(new_rsa.private_key)
        self.assertIsNotNone(new_rsa.public_key)

    def test_encryption_decryption(self):
        """Тестує шифрування та розшифрування файлу"""
        test_data = b"Test message for encryption"
        input_file = os.path.join(self.test_dir, 'input.txt')
        encrypted_file = os.path.join(self.test_dir, 'encrypted.bin')
        decrypted_file = os.path.join(self.test_dir, 'decrypted.txt')

        with open(input_file, 'wb') as f:
            f.write(test_data)

        self.rsa_crypto.encrypt_file(input_file, encrypted_file)
        self.rsa_crypto.decrypt_file(encrypted_file, decrypted_file)

        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()

        self.assertEqual(test_data, decrypted_data)

    def test_large_file_handling(self):
        """Тестує обробку великих файлів"""
        large_data = os.urandom(1024 * 1024)  # 1 MB
        input_file = os.path.join(self.test_dir, 'large_input.bin')
        encrypted_file = os.path.join(self.test_dir, 'large_encrypted.bin')
        decrypted_file = os.path.join(self.test_dir, 'large_decrypted.bin')

        with open(input_file, 'wb') as f:
            f.write(large_data)

        self.rsa_crypto.encrypt_file(input_file, encrypted_file)
        self.rsa_crypto.decrypt_file(encrypted_file, decrypted_file)

        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()

        self.assertEqual(large_data, decrypted_data)

    def tearDown(self):
        """Очищення тестових файлів"""
        for file in os.listdir(self.test_dir):
            os.remove(os.path.join(self.test_dir, file))
        os.rmdir(self.test_dir)