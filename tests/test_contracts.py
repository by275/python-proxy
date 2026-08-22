import asyncio
import io
import socket
import unittest

from pproxy import proto, server


class ParserContractTests(unittest.TestCase):
    def test_netloc_split_supports_defaults_and_ipv6(self):
        self.assertEqual(proto.netloc_split("localhost:8080"), ("localhost", 8080))
        self.assertEqual(proto.netloc_split("[::1]:8443"), ("::1", 8443))
        self.assertEqual(
            proto.netloc_split(":8080", default_host="0.0.0.0", default_port=80),
            ("0.0.0.0", 8080),
        )
        self.assertEqual(
            proto.netloc_split("", default_host="localhost", default_port=8080),
            ("localhost", 8080),
        )

    def test_http_request_head_filters_proxy_headers(self):
        data = (
            b"GET http://example.test/path HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
            b"X-Test: value"
        )

        method, path, version, filtered, host, auth, websocket_key = (
            proto.parse_http_request_head(data)
        )

        self.assertEqual((method, path, version), ("GET", "http://example.test/path", "HTTP/1.1"))
        self.assertEqual(filtered, b"Host: example.test\r\nX-Test: value")
        self.assertEqual(host, "example.test")
        self.assertEqual(auth, "Basic dXNlcjpwYXNz")
        self.assertIsNone(websocket_key)

    def test_http_header_block_and_websocket_mask(self):
        headers, rendered = proto.decode_http_header_block(b"Host: example.test\r\nX-Test: value")
        self.assertEqual(headers, {"Host": "example.test", "X-Test": "value"})
        self.assertEqual(rendered, "Host: example.test\r\nX-Test: value")
        self.assertEqual(proto.xor_mask_bytes(b"hello", b"abcd"), b"\t\x07\x0f\x08\x0e")

    def test_socks_address_round_trip(self):
        raw = io.BytesIO(socket.inet_aton("192.0.2.1") + (443).to_bytes(2, "big"))
        self.assertEqual(proto.socks_address(raw, 1), ("192.0.2.1", 443))

    def test_uri_jump_and_protocol_registry(self):
        self.assertEqual(
            server.split_uri_jumps("http://first:8080__ss://second:8388"),
            ["http://first:8080", "ss://second:8388"],
        )
        error, protocols = proto.get_protos(["http", "socks5"])
        self.assertIsNone(error)
        self.assertEqual([item.name for item in protocols], ["http", "socks5"])

        error, protocols = proto.get_protos(["not-a-protocol"])
        self.assertIsNotNone(error)
        self.assertIsNone(protocols)

    def test_inline_rule_and_cipher_lookup(self):
        rule = server.compile_rule("{^example\\.test$}")
        self.assertIsNotNone(rule("example.test"))
        self.assertIsNone(rule("other.test"))

        from pproxy.cipher import get_cipher

        error, cipher = get_cipher("chacha20:test")
        self.assertIsNone(error)
        self.assertIn(cipher.name, {"chacha20", "chacha20-py"})


class RuntimeContractTests(unittest.TestCase):
    def test_auth_table_state_is_instance_local(self):
        first = server.AuthTable("192.0.2.10", 60)
        second = server.AuthTable("192.0.2.10", 60)

        first.set_authed(b"user:password")

        self.assertEqual(first.authed(), b"user:password")
        self.assertIsNone(second.authed())


class AsyncProtocolContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_guess_peeks_without_consuming_request(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET / HTTP/1.1\r\n")

        self.assertTrue(await proto.HTTP(None).guess(reader))
        self.assertEqual(await reader.read(4), b"GET ")


if __name__ == "__main__":
    unittest.main()
