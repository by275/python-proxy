"""Runtime checks for optional transport security and lifecycle policy."""

import asyncio
import importlib.util
import ssl
import unittest
from unittest.mock import AsyncMock, patch

from pproxy import server
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


if __name__ == "__main__":
    unittest.main()
