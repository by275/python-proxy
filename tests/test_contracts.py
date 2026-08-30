"""Test public protocol and transport interface contracts."""

import asyncio
import io
import socket
import unittest

import pproxy
from pproxy import app, proto, server
from pproxy.config import ProxyConfig, netloc_split
from pproxy.errors import ProtocolError
from pproxy.protocols import address as address_protocol
from pproxy.protocols import base as base_protocol
from pproxy.protocols import http as http_protocol
from pproxy.protocols import registry as registry_protocol
from pproxy.protocols import socks as socks_protocol
from pproxy.protocols import transparent as transparent_protocol
from pproxy.protocols import websocket as websocket_protocol
from pproxy.server import connections as server_connections
from pproxy.server import diagnostics as server_diagnostics
from pproxy.server import factory as server_factory
from pproxy.server import handlers as server_handlers


class ParserContractTests(unittest.TestCase):
    def test_netloc_split_supports_defaults_and_ipv6(self):
        self.assertIs(proto.netloc_split, netloc_split)
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

    def test_http_parser_is_reexported_by_legacy_proto_module(self):
        self.assertIs(proto.parse_http_request_head, http_protocol.parse_http_request_head)
        self.assertIs(proto.decode_http_header_block, http_protocol.decode_http_header_block)

    def test_socks_address_round_trip(self):
        raw = io.BytesIO(socket.inet_aton("192.0.2.1") + (443).to_bytes(2, "big"))
        self.assertEqual(proto.socks_address(raw, 1), ("192.0.2.1", 443))
        self.assertIs(proto.socks_address, address_protocol.socks_address)
        self.assertIs(proto.socks_address_stream, address_protocol.socks_address_stream)

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
    def test_cli_help_lists_all_registered_protocols(self):
        help_text = app._build_parser().format_help()  # pylint: disable=protected-access
        for name, metadata in proto.PROTOCOL_METADATA.items():
            if not metadata.transport_modifier:
                with self.subTest(protocol=name):
                    self.assertIn(name, help_text)

    def test_server_facade_reexports_structured_components(self):
        self.assertIs(server.ProxyDirect, server_connections.ProxyDirect)
        self.assertIs(server.ProxySimple, server_connections.ProxySimple)
        self.assertIs(server.stream_handler, server_handlers.stream_handler)
        self.assertIs(server.proxies_by_uri, server_factory.proxies_by_uri)
        self.assertIs(server.print_server_started, server_diagnostics.print_server_started)

    def test_additive_public_contracts_are_exported(self):
        self.assertIs(pproxy.ProxyConfig, ProxyConfig)
        self.assertIs(pproxy.ProtocolError, ProtocolError)

    def test_protocol_base_is_reexported_by_legacy_module(self):
        self.assertIs(proto.BaseProtocol, base_protocol.BaseProtocol)
        self.assertIs(proto.Direct, base_protocol.Direct)

    def test_http_protocol_classes_are_reexported_by_legacy_module(self):
        self.assertIs(proto.HTTP, http_protocol.HTTP)
        self.assertIs(proto.HTTPOnly, http_protocol.HTTPOnly)
        self.assertIs(proto.H2, http_protocol.H2)
        self.assertIs(proto.H3, http_protocol.H3)
        self.assertIs(proto.HTTPAdmin, http_protocol.HTTPAdmin)

    def test_socks_protocol_classes_are_reexported_by_legacy_module(self):
        self.assertIs(proto.Trojan, socks_protocol.Trojan)
        self.assertIs(proto.SSR, socks_protocol.SSR)
        self.assertIs(proto.SS, socks_protocol.SS)
        self.assertIs(proto.Socks4, socks_protocol.Socks4)
        self.assertIs(proto.Socks5, socks_protocol.Socks5)

    def test_socket_protocol_classes_are_reexported_by_legacy_module(self):
        self.assertIs(proto.SSH, transparent_protocol.SSH)
        self.assertIs(proto.Transparent, transparent_protocol.Transparent)
        self.assertIs(proto.Redir, transparent_protocol.Redir)
        self.assertIs(proto.Pf, transparent_protocol.Pf)
        self.assertIs(proto.Tunnel, transparent_protocol.Tunnel)
        self.assertIs(proto.Echo, transparent_protocol.Echo)
        self.assertIs(proto.WS, websocket_protocol.WS)

    def test_registry_is_reexported_by_legacy_module(self):
        self.assertIs(proto.MAPPINGS, registry_protocol.MAPPINGS)
        self.assertIs(proto.PROTOCOL_METADATA, registry_protocol.PROTOCOL_METADATA)
        self.assertIs(proto.ProtocolMetadata, registry_protocol.ProtocolMetadata)
        self.assertIs(proto.get_protos, registry_protocol.get_protos)
        self.assertIs(proto.get_protocol_metadata, registry_protocol.get_protocol_metadata)
        self.assertIs(proto.accept, registry_protocol.accept)
        self.assertIs(proto.udp_accept, registry_protocol.udp_accept)

    def test_registry_metadata_describes_transport_capabilities(self):
        http_metadata = proto.get_protocol_metadata("http")
        socks_metadata = proto.get_protocol_metadata("socks5")
        h2_metadata = proto.get_protocol_metadata("h2")

        self.assertTrue(http_metadata.supports_tcp)
        self.assertFalse(http_metadata.supports_udp)
        self.assertTrue(socks_metadata.supports_udp)
        self.assertEqual(h2_metadata.optional_dependency, "h2")
        self.assertEqual(h2_metadata.default_port, 8080)
        self.assertTrue(proto.get_protocol_metadata("ssl").transport_modifier)
        self.assertIsNone(proto.get_protocol_metadata("unknown"))

    def test_register_protocol_can_publish_optional_metadata(self):
        class FutureProtocol:
            def __init__(self, param):
                self.param = param

        metadata = registry_protocol.ProtocolMetadata(
            supports_tcp=True,
            supports_udp=False,
            supports_client=True,
            supports_server=True,
            optional_dependency="future-package",
            default_port=9000,
        )
        try:
            proto.register_protocol("future-metadata", FutureProtocol, metadata)
            self.assertIs(proto.get_protocol_metadata("future-metadata"), metadata)
        finally:
            registry_protocol.MAPPINGS.pop("future-metadata", None)
            registry_protocol.PROTOCOL_METADATA.pop("future-metadata", None)

    def test_registry_accepts_future_optional_protocols(self):
        class FutureProtocol:
            def __init__(self, param):
                self.param = param

        try:
            proto.register_protocol('cfp-test', FutureProtocol)
            error, protocols = proto.get_protos(['cfp-test{future}'])
            self.assertIsNone(error)
            self.assertIsInstance(protocols[0], FutureProtocol)
            self.assertEqual(protocols[0].param, 'future')
        finally:
            registry_protocol.MAPPINGS.pop('cfp-test', None)

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

    async def test_socks_address_stream_preserves_domain_wire_data(self):
        reader = asyncio.StreamReader()
        wire = b"\x0cexample.test" + (443).to_bytes(2, "big")
        reader.feed_data(wire)

        host, port, encoded = await proto.socks_address_stream(reader, 3)

        self.assertEqual((host, port), ("example.test", 443))
        self.assertEqual(encoded, wire)


if __name__ == "__main__":
    unittest.main()
