"""Test cipher registry selection and packet cipher behavior."""

import unittest

from pproxy.cipher import PacketCipher, get_cipher
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

    def test_stream_cipher_round_trip(self):
        class Reader:
            def __init__(self):
                self.received = []
                self._buffer = bytearray()

            def feed_data(self, data):
                self.received.append(data)

        class Writer:
            def __init__(self):
                self.writes = []

            def write(self, data):
                self.writes.append(data)

        error, apply_cipher = get_cipher("chacha20-py:test-key")
        self.assertIsNone(error)
        reader, writer = Reader(), Writer()
        apply_cipher(
            reader, writer,
            lambda data: data, lambda data: data,
            lambda data: data, lambda data: data,
        )

        writer.write(b"stream payload")
        reader.feed_data(b"".join(writer.writes))

        self.assertEqual(b"".join(reader.received), b"stream payload")


if __name__ == "__main__":
    unittest.main()
