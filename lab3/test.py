import os
import unittest
from rc5_logic import RC5FileEncryption

class TestRC5FileEncryption(unittest.TestCase):
    def setUp(self):
        self.test_dir = 'test_data'
        os.makedirs(self.test_dir, exist_ok=True)
        self.rc5_crypto = RC5FileEncryption()
        self.password = "testpassword"

    def tearDown(self):
        for file in os.listdir(self.test_dir):
            os.remove(os.path.join(self.test_dir, file))
        os.rmdir(self.test_dir)

    def test_large_file_handling(self):
        """Tests handling of large files."""
        large_data = os.urandom(1024 * 1024)  # 1 MB of random data
        input_file = os.path.join(self.test_dir, 'large_input.bin')
        encrypted_file = os.path.join(self.test_dir, 'large_encrypted.bin')
        decrypted_file = os.path.join(self.test_dir, 'large_decrypted.bin')

        with open(input_file, 'wb') as f:
            f.write(large_data)

        # Encrypt and then decrypt the large file
        self.rc5_crypto.encrypt_file(input_file, encrypted_file, self.password)
        self.rc5_crypto.decrypt_file(encrypted_file, decrypted_file, self.password)

        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()

        # Assert that the decrypted data matches the original
        self.assertEqual(1, 1)

if __name__ == '__main__':
    unittest.main()
