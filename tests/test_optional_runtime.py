"""Runtime checks for optional transport security and lifecycle policy."""

import asyncio
import builtins
import contextlib
import importlib.util
import socket
import ssl
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from unittest.mock import AsyncMock, patch

from pproxy import server
from pproxy.errors import ConfigurationError
from pproxy.h2 import ProxyH2
from pproxy.protocols.http import H2


class OptionalRuntimePolicyTests(unittest.TestCase):
    def test_h2_stream_limit_is_explicit(self):
        self.assertGreater(ProxyH2.MAX_STREAMS, 0)

    def test_h2_connect_uses_rfc7540_authority_form(self):
        class Writer:
            def __init__(self):
                self.headers = None

            def send_headers(self, headers):
                self.headers = headers

        async def exercise():
            writer = Writer()
            await H2(None).connect(None, writer, b'', 'example.test', 443, 'proxy.test')
            return writer.headers

        headers = asyncio.run(exercise())
        self.assertEqual(headers, [(':method', 'CONNECT'), (':authority', 'example.test:443')])

    @unittest.skipUnless(importlib.util.find_spec("aioquic"), "aioquic is not installed")
    def test_quic_verification_is_secure_by_default(self):
        secure = server.proxies_by_uri("quic+http://127.0.0.1:443")
        insecure = server.proxies_by_uri("quic+ssl+http://127.0.0.1:443")

        self.assertEqual(secure.quicclient.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(insecure.quicclient.verify_mode, ssl.CERT_NONE)


class SSHHostKeyPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_asyncssh_does_not_leave_a_pending_connection(self):
        option = server.proxies_by_uri("ssh://127.0.0.1:22/#user:secret")
        original_import = builtins.__import__

        def import_without_asyncssh(name, *args, **kwargs):
            if name == 'asyncssh':
                raise ImportError('test dependency missing')
            return original_import(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=import_without_asyncssh):
            with self.assertRaises(ConfigurationError):
                await option.wait_ssh_connection()

        self.assertIsNone(option.sshconn)

    @unittest.skipUnless(importlib.util.find_spec("asyncssh"), "asyncssh is not installed")
    async def test_known_hosts_verification_is_default(self):
        option = server.proxies_by_uri("ssh://127.0.0.1:22/#user:secret")
        with patch("asyncssh.connect", new=AsyncMock(return_value=object())) as connect:
            await option.wait_ssh_connection()

        self.assertNotIn("known_hosts", connect.call_args.kwargs)

    @unittest.skipUnless(importlib.util.find_spec("asyncssh"), "asyncssh is not installed")
    async def test_insecure_host_key_override_is_explicit(self):
        option = server.proxies_by_uri("ssh+insecure://127.0.0.1:22/#user:secret")
        with patch("asyncssh.connect", new=AsyncMock(return_value=object())) as connect:
            await option.wait_ssh_connection()

        self.assertIsNone(connect.call_args.kwargs["known_hosts"])


class H2LoopbackTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(importlib.util.find_spec("h2"), "h2 is not installed")
    async def test_h2_loopback_round_trip_and_shutdown(self):
        async def echo(reader, writer):
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()

        echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        echo_port = echo_server.sockets[0].getsockname()[1]
        listener = server.proxies_by_uri("h2+http://127.0.0.1:0")
        handler = await listener.start_server({"rserver": [], "verbose": lambda *_: None})
        proxy_port = handler.sockets[0].getsockname()[1]
        client = server.proxies_by_uri(f"h2+http://127.0.0.1:{proxy_port}")
        try:
            reader, writer = await asyncio.wait_for(
                client.tcp_connect("127.0.0.1", echo_port),
                5,
            )
            writer.write(b"h2-smoke")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(8), 5), b"h2-smoke")
            writer.close()
        finally:
            client.close()
            listener.close()
            handler.close()
            echo_server.close()
            await asyncio.sleep(0.1)
            await client.wait_closed()
            await listener.wait_closed()
            await handler.wait_closed()
            await echo_server.wait_closed()


def _write_quic_certificate(directory):
    """Create a short-lived localhost certificate for an aioquic fixture."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip_address('127.0.0.1'))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = f'{directory}/certificate.pem'
    key_path = f'{directory}/key.pem'
    certificate_data = certificate.public_bytes(serialization.Encoding.PEM)
    with open(cert_path, 'wb') as cert_file:
        cert_file.write(certificate_data)
    with open(key_path, 'wb') as key_file:
        key_file.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    return cert_path, key_path, certificate_data


@contextlib.asynccontextmanager
async def quic_fixture(protocol_name):
    async def echo(reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    with tempfile.TemporaryDirectory() as directory:
        cert_path, key_path, certificate_data = _write_quic_certificate(directory)
        echo_server = await asyncio.start_server(echo, '127.0.0.1', 0)
        echo_port = echo_server.sockets[0].getsockname()[1]
        listener = server.proxies_by_uri(f'{protocol_name}+http://127.0.0.1:0')
        listener.quicserver.load_cert_chain(cert_path, key_path)
        handler = await listener.start_server({'rserver': [], 'verbose': lambda *_: None})
        proxy_port = handler._transport.get_extra_info('sockname')[1]  # pylint: disable=protected-access
        client = server.proxies_by_uri(f'{protocol_name}+http://127.0.0.1:{proxy_port}')
        client.quicclient.load_verify_locations(cadata=certificate_data)
        try:
            yield client, listener, handler, echo_server, echo_port
        finally:
            client.close()
            listener.close()
            handler.close()
            echo_server.close()
            await asyncio.sleep(0.1)
            await client.wait_closed()
            await listener.wait_closed()
            await echo_server.wait_closed()


class QuicLifecycleTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(importlib.util.find_spec('aioquic'), 'aioquic is not installed')
    async def test_quic_and_h3_round_trip_and_shutdown(self):
        for protocol_name in ('quic', 'h3'):
            with self.subTest(protocol=protocol_name):
                async with quic_fixture(protocol_name) as (client, _listener, _handler, _echo, echo_port):
                    for index in range(3):
                        reader, writer = await asyncio.wait_for(
                            client.tcp_connect('127.0.0.1', echo_port),
                            5,
                        )
                        payload = f'{protocol_name}-smoke-{index}'.encode()
                        writer.write(payload)
                        await writer.drain()
                        self.assertEqual(
                            await asyncio.wait_for(reader.readexactly(len(payload)), 5),
                            payload,
                        )
                        writer.close()
                        await asyncio.sleep(0.02)
                    self.assertFalse(client.writers)

    @unittest.skipUnless(importlib.util.find_spec('aioquic'), 'aioquic is not installed')
    async def test_reconnects_after_remote_quic_connection_termination(self):
        for protocol_name in ('quic', 'h3'):
            with self.subTest(protocol=protocol_name):
                async with quic_fixture(protocol_name) as (client, listener, handler, _echo, echo_port):
                    reader, writer = await asyncio.wait_for(
                        client.tcp_connect('127.0.0.1', echo_port),
                        5,
                    )
                    writer.write(b'first-connection')
                    await writer.drain()
                    self.assertEqual(
                        await asyncio.wait_for(reader.readexactly(16), 5),
                        b'first-connection',
                    )
                    writer.close()
                    remote_protocol = next(iter(handler._protocols.values()))  # pylint: disable=protected-access
                    remote_protocol.close()
                    await asyncio.wait_for(client.wait_closed(), 1)
                    handler.close()

                    replacement = await listener.start_server(
                        {'rserver': [], 'verbose': lambda *_: None}
                    )
                    client.port = replacement._transport.get_extra_info('sockname')[1]  # pylint: disable=protected-access
                    try:
                        reader, writer = await asyncio.wait_for(
                            client.tcp_connect('127.0.0.1', echo_port),
                            5,
                        )
                        writer.write(b'reconnected')
                        await writer.drain()
                        self.assertEqual(
                            await asyncio.wait_for(reader.readexactly(11), 5),
                            b'reconnected',
                        )
                        writer.close()
                    finally:
                        replacement.close()

    @unittest.skipUnless(importlib.util.find_spec('aioquic'), 'aioquic is not installed')
    async def test_cancelled_handshake_does_not_leave_connection_task(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(('127.0.0.1', 0))
            unused_port = probe.getsockname()[1]
        client = server.proxies_by_uri(f'quic+http://127.0.0.1:{unused_port}')
        try:
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(client.wait_quic_connection(), 0.1)
            await client.wait_closed()
            self.assertIsNone(client.quic_protocol)
            self.assertIsNone(client.handshake)
            self.assertFalse(client.task_registry)
        finally:
            client.close()
            await client.wait_closed()


if __name__ == "__main__":
    unittest.main()
