"""Negative tests for malformed protocol and cipher input."""

import asyncio
import unittest

from pproxy import proto, server
from pproxy.cipherpy import MAP as pure_cipher_map
from pproxy.errors import ProtocolError


class CaptureWriter:
    def __init__(self):
        self.writes = []

    def write(self, data):
        self.writes.append(data)


class MalformedParserTests(unittest.TestCase):
    def test_http_parser_rejects_an_invalid_request_line(self):
        with self.assertRaises(ProtocolError):
            proto.parse_http_request_head(b"NOT-A-REQUEST\r\nHost: example.test")

    def test_websocket_parser_does_not_emit_a_truncated_frame(self):
        reader = type("Reader", (), {"feed_data": lambda self, data: None})()
        writer = CaptureWriter()
        received = []
        reader.feed_data = received.append
        proto.WS(None).patch_ws_stream(reader, writer)

        reader.feed_data(b"\x82\xfe\x00")

        self.assertEqual(received, [])
        self.assertEqual(writer.writes, [])


class MalformedProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_socks5_rejects_a_mismatched_request_version(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x01\x05\x04\x01\x00")
        writer = CaptureWriter()

        with self.assertRaises(ProtocolError):
            await proto.Socks5(None).accept(
                reader,
                None,
                writer,
                users=None,
                authtable=server.AuthTable("192.0.2.1", 60),
            )

    async def test_socks_address_stream_rejects_an_unknown_address_type(self):
        reader = asyncio.StreamReader()
        with self.assertRaises(ProtocolError):
            await proto.socks_address_stream(reader, 99)


class MalformedCipherTests(unittest.TestCase):
    def test_pure_python_aead_rejects_a_tampered_tag(self):
        cipher_class = pure_cipher_map["chacha20-ietf-poly1305"]
        key = b"malformed-input-test"
        iv = bytes(range(cipher_class.IV_LENGTH))
        payload = b"authenticated payload"

        encryptor = cipher_class(key).setup_iv(iv)
        ciphertext, tag = encryptor.encrypt_and_digest(payload)
        invalid_tag = bytes([tag[0] ^ 1]) + tag[1:]
        decryptor = cipher_class(key).setup_iv(iv)

        with self.assertRaises(ProtocolError):
            decryptor.decrypt_and_verify(ciphertext, invalid_tag)


if __name__ == "__main__":
    unittest.main()
