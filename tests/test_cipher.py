import unittest

from pproxy.cipher import PacketCipher
from pproxy.cipherpy import MAP


class PurePythonCipherTests(unittest.TestCase):
    def test_chacha20_round_trip(self):
        cipher_class = MAP["chacha20"]
        key = b"test-key"
        iv = bytes(range(cipher_class.IV_LENGTH))
        payload = b"proxy payload" * 32

        encryptor = cipher_class(key).setup_iv(iv)
        ciphertext = encryptor.encrypt(payload)
        decryptor = cipher_class(key).setup_iv(iv)

        self.assertEqual(decryptor.decrypt(ciphertext), payload)

    def test_packet_cipher_round_trip(self):
        cipher_class = MAP["chacha20"]
        packet_cipher = PacketCipher(cipher_class, b"test-key", "chacha20")
        payload = b"one packet"

        encrypted = packet_cipher.encrypt(payload)

        self.assertEqual(packet_cipher.decrypt(encrypted), payload)


if __name__ == "__main__":
    unittest.main()
