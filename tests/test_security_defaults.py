"""Regression tests for secure defaults and connection ownership."""

import asyncio
import base64
import unittest

from pproxy import server
from pproxy.cipher import get_cipher
from pproxy.protocols.http import HTTPAdmin


class CaptureWriter:
    def __init__(self):
        self.writes = []
        self.closed = False

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True


class SecurityDefaultTests(unittest.TestCase):
    def test_default_listener_is_loopback_only(self):
        option = server.proxies_by_uri("http+socks4+socks5://127.0.0.1:8080/")

        self.assertEqual(option.host_name, "127.0.0.1")
        self.assertFalse(server.is_unauthenticated_wildcard(option))

    def test_httpadmin_requires_credentials(self):
        with self.assertRaises(Exception):
            server.proxies_by_uri("httpadmin://127.0.0.1:8081/")

    def test_httpadmin_defaults_to_loopback(self):
        option = server.proxies_by_uri("httpadmin://:8081/#admin:secret")

        self.assertEqual(option.host_name, "127.0.0.1")

    def test_cipher_sessions_clone_plugin_state(self):
        error, factory = get_cipher("chacha20-py:test-key")
        self.assertIsNone(error)
        factory.plugins.append(type("Plugin", (), {})())

        first = factory.for_connection()
        second = factory.for_connection()

        self.assertIsNot(first, second)
        self.assertIsNot(first.plugins[0], second.plugins[0])
        self.assertIs(factory.plugins[0].__class__, second.plugins[0].__class__)


class AdminAuthenticationTests(unittest.IsolatedAsyncioTestCase):
    async def test_admin_rejects_missing_authentication(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
        writer = CaptureWriter()

        with self.assertRaises(Exception):
            await HTTPAdmin(None).accept(reader, True, writer, users=[b"admin:secret"])

        self.assertIn(b"401 Unauthorized", b"".join(writer.writes))

    async def test_admin_accepts_authorized_status_request(self):
        token = base64.b64encode(b"admin:secret").decode()
        reader = asyncio.StreamReader()
        reader.feed_data(
            f"GET /status HTTP/1.1\r\nAuthorization: Basic {token}\r\n\r\n".encode()
        )
        writer = CaptureWriter()

        with self.assertRaisesRegex(Exception, "Connection closed"):
            await HTTPAdmin(None).accept(reader, True, writer, users=[b"admin:secret"])

        self.assertIn(b"200 OK", b"".join(writer.writes))


if __name__ == "__main__":
    unittest.main()
