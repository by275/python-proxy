"""Phase 1 integration coverage for local and optional runtime boundaries."""

import asyncio
import base64
import contextlib
import importlib.util
import os
import socket
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pproxy import server, sysproxy
from pproxy.protocols.transparent import Pf, Redir, Tunnel


async def _read_http_response(port, request):
    """Send one request to a local TCP listener and read its closed response."""
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    writer.write(request)
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), 5)
    writer.close()
    await writer.wait_closed()
    return response


class AdminIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Exercise authenticated administration requests through a real listener."""

    async def test_authenticated_status_and_config_requests_shutdown_cleanly(self):
        option = server.proxies_by_uri('httpadmin://127.0.0.1:0/#admin:secret')
        listener = await option.start_server({'rserver': [], 'verbose': lambda *_: None})
        port = listener.sockets[0].getsockname()[1]
        token = base64.b64encode(b'admin:secret').decode()
        try:
            unauthorized = await _read_http_response(
                port,
                b'GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n',
            )
            self.assertIn(b'401 Unauthorized', unauthorized)

            authorization = f'Authorization: Basic {token}\r\n'.encode()
            status = await _read_http_response(
                port,
                b'GET /status HTTP/1.1\r\n' + authorization + b'\r\n',
            )
            self.assertIn(b'200 OK', status)
            self.assertIn(b'{"status": "ok"}', status)

            configs = await _read_http_response(
                port,
                b'GET /configs HTTP/1.1\r\n' + authorization + b'\r\n',
            )
            self.assertIn(b'200 OK', configs)
            self.assertIn(b'"actions": ["reload"]', configs)
            self.assertNotIn(b'admin:secret', configs)
        finally:
            option.close()
            listener.close()
            await option.wait_closed()
            await listener.wait_closed()


class UnixSocketIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Exercise a real Unix-domain listener and its coordinated shutdown."""

    async def test_echo_listener_round_trip_and_shutdown(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = os.path.join(directory, 'echo.sock')
            option = server.proxies_by_uri(f'echo://{socket_path}')
            listener = await option.start_server({'rserver': [], 'verbose': lambda *_: None})
            try:
                reader, writer = await asyncio.open_unix_connection(socket_path)
                writer.write(b'unix-domain-smoke')
                await writer.drain()
                self.assertEqual(
                    await asyncio.wait_for(reader.readexactly(17), 5),
                    b'unix-domain-smoke',
                )
                writer.close()
                await writer.wait_closed()
            finally:
                option.close()
                listener.close()
                await option.wait_closed()
                await listener.wait_closed()


class TransparentAndSystemProxyBoundaryTests(unittest.TestCase):
    """Verify platform adapters fail safely outside their native environments."""

    def test_transparent_protocols_handle_unavailable_socket_metadata(self):
        class SocketWithoutOriginalDestination:
            family = socket.AF_INET

            @staticmethod
            def getsockname():
                return ('127.0.0.1', 12345)

            @staticmethod
            def getpeername():
                return ('127.0.0.1', 54321)

            @staticmethod
            def getsockopt(_level, _option, _size):
                return b''

            @staticmethod
            def fileno():
                return -1

        sock = SocketWithoutOriginalDestination()
        self.assertIsNone(Redir(None).query_remote(sock))
        self.assertIsNone(Pf(None).query_remote(sock))
        self.assertEqual(Tunnel(None).query_remote(None), ('tunnel', 0))

    def test_system_proxy_dispatch_and_linux_boundary(self):
        args = SimpleNamespace(listen=[])
        with patch.object(sysproxy.sys, 'platform', 'linux'):
            self.assertIsNone(sysproxy.setup(args))
        with patch.object(sysproxy, 'MacSetting') as mac_setting:
            with patch.object(sysproxy.sys, 'platform', 'darwin'):
                self.assertIs(sysproxy.setup(args), mac_setting.return_value)
            mac_setting.assert_called_once_with(args)
        with patch.object(sysproxy, 'WindowsSetting') as windows_setting:
            with patch.object(sysproxy.sys, 'platform', 'win32'):
                self.assertIs(sysproxy.setup(args), windows_setting.return_value)
            windows_setting.assert_called_once_with(args)


@unittest.skipUnless(importlib.util.find_spec('asyncssh'), 'asyncssh is not installed')
class SSHIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Exercise SSH forwarding and host-key policy with an in-process server."""

    async def asyncSetUp(self):
        import asyncssh

        self.asyncssh = asyncssh
        self.server_key = asyncssh.generate_private_key('ssh-ed25519')

        async def echo(reader, writer):
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()

        class SSHServer(asyncssh.SSHServer):
            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                return username == 'user' and password == 'secret'

            def connection_requested(self, _dest_host, _dest_port, _orig_host, _orig_port):
                return echo

        self.ssh_listener = await asyncssh.create_server(
            SSHServer,
            '127.0.0.1',
            0,
            server_host_keys=[self.server_key],
        )
        self.ssh_port = self.ssh_listener.get_port()

    async def asyncTearDown(self):
        self.ssh_listener.close()
        await self.ssh_listener.wait_closed()

    def _known_hosts(self, key):
        return f'[127.0.0.1]:{self.ssh_port} '.encode() + key.export_public_key()

    def _connect_with_known_hosts(self, known_hosts):
        original_connect = self.asyncssh.connect

        async def connect(*args, **kwargs):
            kwargs['known_hosts'] = known_hosts
            return await original_connect(*args, **kwargs)

        return connect

    async def test_secure_forwarding_checks_host_key_and_closes(self):
        option = server.proxies_by_uri(
            f'ssh://127.0.0.1:{self.ssh_port}/#user:secret'
        )
        try:
            with patch('asyncssh.connect', new=self._connect_with_known_hosts(
                self._known_hosts(self.server_key),
            )):
                reader, writer = await asyncio.wait_for(
                    option.tcp_connect('example.test', 443),
                    5,
                )
                writer.write(b'ssh-forward-smoke')
                await writer.drain()
                self.assertEqual(
                    await asyncio.wait_for(reader.readexactly(17), 5),
                    b'ssh-forward-smoke',
                )
                writer.close()
            option.close()
            await asyncio.wait_for(option.wait_closed(), 5)
        finally:
            option.close()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await option.wait_closed()

    async def test_mismatched_host_key_fails_and_insecure_override_is_explicit(self):
        wrong_key = self.asyncssh.generate_private_key('ssh-ed25519')
        secure = server.proxies_by_uri(
            f'ssh://127.0.0.1:{self.ssh_port}/#user:secret'
        )
        try:
            with patch('asyncssh.connect', new=self._connect_with_known_hosts(
                self._known_hosts(wrong_key),
            )):
                with self.assertRaises(self.asyncssh.HostKeyNotVerifiable):
                    await secure.tcp_connect('example.test', 443)
        finally:
            secure.close()
            await secure.wait_closed()

        insecure = server.proxies_by_uri(
            f'ssh+insecure://127.0.0.1:{self.ssh_port}/#user:secret'
        )
        try:
            original_connect = self.asyncssh.connect

            async def connect_insecure(*args, **kwargs):
                self.assertIsNone(kwargs['known_hosts'])
                return await original_connect(*args, **kwargs)

            with patch('asyncssh.connect', new=connect_insecure):
                reader, writer = await asyncio.wait_for(
                    insecure.tcp_connect('example.test', 443),
                    5,
                )
                writer.write(b'insecure-smoke')
                await writer.drain()
                self.assertEqual(
                    await asyncio.wait_for(reader.readexactly(14), 5),
                    b'insecure-smoke',
                )
                writer.close()
        finally:
            insecure.close()
            await insecure.wait_closed()


if __name__ == '__main__':
    unittest.main()
