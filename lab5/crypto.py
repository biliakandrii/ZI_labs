# crypto_operations.py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass
from typing import Tuple, Optional
import os

@dataclass
class KeyPair:
    private_key: dsa.DSAPrivateKey
    public_key: dsa.DSAPublicKey

class CryptoOperations:
    def __init__(self):
        self.current_keys: Optional[KeyPair] = None

    def generate_key_pair(self) -> KeyPair:
        """Generate a new DSA key pair"""
        private_key = dsa.generate_private_key(key_size=2048)
        public_key = private_key.public_key()
        self.current_keys = KeyPair(private_key, public_key)
        return self.current_keys

    def save_keys(self, private_path: str, public_path: str) -> None:
        """Save the current key pair to files"""
        if not self.current_keys:
            raise ValueError("No keys available to save")

        # Save private key
        private_pem = self.current_keys.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_path, "wb") as f:
            f.write(private_pem)

        # Save public key
        public_pem = self.current_keys.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_path, "wb") as f:
            f.write(public_pem)

    def load_keys(self, private_path: str, public_path: str) -> KeyPair:
        """Load key pair from files"""
        # Load private key
        with open(private_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        # Load public key
        with open(public_path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read()
            )

        self.current_keys = KeyPair(private_key, public_key)
        return self.current_keys

    def sign_data(self, data: bytes) -> bytes:
        """Create a digital signature for the given data"""
        if not self.current_keys:
            raise ValueError("No keys available for signing")

        signature = self.current_keys.private_key.sign(
            data,
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify a digital signature"""
        if not self.current_keys:
            raise ValueError("No keys available for verification")

        try:
            self.current_keys.public_key.verify(
                signature,
                data,
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def sign_file(self, file_path: str) -> bytes:
        """Create a digital signature for a file"""
        with open(file_path, "rb") as f:
            data = f.read()
        return self.sign_data(data)

    def verify_file_signature(self, file_path: str, signature: bytes) -> bool:
        """Verify a file's digital signature"""
        with open(file_path, "rb") as f:
            data = f.read()
        return self.verify_signature(data, signature)