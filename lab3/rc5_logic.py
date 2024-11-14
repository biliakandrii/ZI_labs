# rc5_logic.py
import hashlib
import time

class RC5:
    def __init__(self, w=32, r=12, b=16):
        self.w = w
        self.r = r
        self.b = b
        self.T = 2 * (r + 1)
        self.w4 = w // 4
        self.w8 = w // 8
        self.mod = 2 ** w
        self.mask = self.mod - 1

        self.Pw = 0xB7E15163
        self.Qw = 0x9E3779B9

    def _left_rotate(self, val, n):
        n = n % self.w
        return ((val << n) & self.mask) | ((val & self.mask) >> (self.w - n))

    def _right_rotate(self, val, n):
        n = n % self.w
        return ((val & self.mask) >> n) | (val << (self.w - n) & self.mask)

    def expand_key(self, key):
        L = []
        for i in range(0, len(key), self.w8):
            L.append(int.from_bytes(key[i:i + self.w8], byteorder='little'))

        S = [self.Pw]
        for i in range(1, self.T):
            S.append((S[i - 1] + self.Qw) & self.mask)

        i = j = 0
        A = B = 0
        for k in range(3 * max(len(L), self.T)):
            A = S[i] = self._left_rotate((S[i] + A + B) & self.mask, 3)
            B = L[j] = self._left_rotate((L[j] + A + B) & self.mask, (A + B) & self.mask)
            i = (i + 1) % self.T
            j = (j + 1) % len(L)

        return S

    def encrypt_block(self, data, S):
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')

        A = (A + S[0]) & self.mask
        B = (B + S[1]) & self.mask

        for i in range(1, self.r + 1):
            A = (self._left_rotate(A ^ B, B) + S[2 * i]) & self.mask
            B = (self._left_rotate(B ^ A, A) + S[2 * i + 1]) & self.mask

        return A.to_bytes(self.w8, byteorder='little') + B.to_bytes(self.w8, byteorder='little')

    def decrypt_block(self, data, S):
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')

        for i in range(self.r, 0, -1):
            B = self._right_rotate(B - S[2 * i + 1], A) ^ A
            A = self._right_rotate(A - S[2 * i], B) ^ B

        B = (B - S[1]) & self.mask
        A = (A - S[0]) & self.mask

        return A.to_bytes(self.w8, byteorder='little') + B.to_bytes(self.w8, byteorder='little')


class RC5FileEncryption:
    def __init__(self, word_size=32, rounds=12, key_size=16):
        self.rc5 = RC5(word_size, rounds, key_size)
        self.block_size = word_size // 4

    def generate_iv(self):
        seed = int(time.time() * 1000)
        a = 1664525
        c = 1013904223
        m = 2 ** 32
        rand_val = (a * seed + c) % m
        return rand_val.to_bytes(self.block_size, byteorder='little')

    def pad_data(self, data):
        padding_length = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad_data(self, data):
        padding_length = data[-1]
        return data[:-padding_length]

    def derive_key(self, password):
        md5 = hashlib.md5()
        md5.update(password.encode())
        key_hash = md5.digest()
        return key_hash[:16]

    def encrypt_file(self, input_file, output_file, password):
        key = self.derive_key(password)
        S = self.rc5.expand_key(key)

        iv = self.generate_iv()
        encrypted_iv = self.rc5.encrypt_block(iv, S)

        with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
            fout.write(encrypted_iv)

            prev_block = iv
            while True:
                block = fin.read(self.block_size)
                if not block:
                    break

                if len(block) < self.block_size:
                    block = self.pad_data(block)

                block_int = int.from_bytes(block, byteorder='little')
                prev_int = int.from_bytes(prev_block, byteorder='little')
                xored = (block_int ^ prev_int).to_bytes(self.block_size, byteorder='little')

                encrypted_block = self.rc5.encrypt_block(xored, S)
                fout.write(encrypted_block)
                prev_block = encrypted_block

    def decrypt_file(self, input_file, output_file, password):
        key = self.derive_key(password)
        S = self.rc5.expand_key(key)

        with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
            encrypted_iv = fin.read(self.block_size)
            iv = self.rc5.decrypt_block(encrypted_iv, S)

            prev_block = iv
            encrypted_blocks = []

            while True:
                block = fin.read(self.block_size)
                if not block:
                    break
                encrypted_blocks.append(block)

            for i, block in enumerate(encrypted_blocks):
                decrypted = self.rc5.decrypt_block(block, S)

                prev_int = int.from_bytes(prev_block, byteorder='little')
                decrypted_int = int.from_bytes(decrypted, byteorder='little')
                plaintext = (decrypted_int ^ prev_int).to_bytes(self.block_size, byteorder='little')

                prev_block = block

                if i == len(encrypted_blocks) - 1:
                    plaintext = self.unpad_data(plaintext)
                fout.write(plaintext)
