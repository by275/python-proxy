"""Smoke tests for connection and task cleanup."""

import asyncio
import contextlib
import unittest

import pproxy
from pproxy import server
from pproxy.runtime import TaskRegistry


async def echo_handler(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def settle_tasks():
    for _ in range(20):
        await asyncio.sleep(0.01)


class ConnectionLeakSmokeTests(unittest.IsolatedAsyncioTestCase):
    async def test_repeated_short_lived_connections_leave_no_pending_tasks(self):
        echo_server = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
        proxy_option = server.proxies_by_uri("http://127.0.0.1:0")
        proxy_server = await proxy_option.start_server(
            {"rserver": [], "verbose": lambda *_: None}
        )
        echo_port = echo_server.sockets[0].getsockname()[1]
        proxy_port = proxy_server.sockets[0].getsockname()[1]
        current_task = asyncio.current_task()
        baseline = {
            task
            for task in asyncio.all_tasks()
            if task is not current_task and not task.done()
        }

        try:
            for index in range(8):
                reader, writer = await pproxy.Connection(
                    f"http://127.0.0.1:{proxy_port}"
                ).tcp_connect("127.0.0.1", echo_port)
                try:
                    payload = f"leak-smoke-{index}".encode()
                    writer.write(payload)
                    await writer.drain()
                    self.assertEqual(await reader.readexactly(len(payload)), payload)
                    if writer.can_write_eof():
                        writer.write_eof()
                        await writer.drain()
                finally:
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()

            await settle_tasks()
            leaked = {
                task
                for task in asyncio.all_tasks()
                if task not in baseline and task is not current_task and not task.done()
            }
            self.assertFalse(leaked, [task.get_coro().__qualname__ for task in leaked])
        finally:
            proxy_server.close()
            await proxy_server.wait_closed()
            echo_server.close()
            await echo_server.wait_closed()
            await settle_tasks()

    async def test_task_registry_is_empty_after_repeated_shutdown(self):
        registry = TaskRegistry()

        for _ in range(8):
            registry.create_task(asyncio.sleep(0))
            await registry.wait_closed()

        self.assertFalse(registry)


class UdpLeakSmokeTests(unittest.TestCase):
    def test_eviction_closes_and_removes_the_oldest_protocol(self):
        proxy = server.ProxyDirect()

        class DatagramProtocol:
            transport = None

        protocols = [DatagramProtocol() for _ in range(server.UDP_LIMIT + 1)]
        for index, protocol in enumerate(protocols):
            proxy.udp_touch(("127.0.0.1", index), protocol)

        proxy.udp_evict_if_needed()

        self.assertNotIn(("127.0.0.1", 0), proxy.udpmap)
        self.assertEqual(len(proxy.udpmap), server.UDP_LIMIT)

    def test_udp_connection_lost_removes_client_mapping_not_upstream_peer(self):
        async def exercise():
            proxy = server.ProxyDirect()
            loop = asyncio.get_running_loop()
            original = loop.create_datagram_endpoint

            class DatagramTransport:
                def sendto(self, data):
                    return None

                def close(self):
                    return None

            async def create_datagram_endpoint(factory, remote_addr):
                protocol = factory()
                protocol.connection_made(DatagramTransport())
                protocol.datagram_received(b"upstream reply", ("198.51.100.10", 53))
                protocol.connection_lost(None)
                return protocol.transport, protocol

            loop.create_datagram_endpoint = create_datagram_endpoint
            try:
                await proxy.udp_open_connection(
                    "198.51.100.10",
                    53,
                    b"request",
                    ("127.0.0.1", 40000),
                    lambda data: None,
                )
            finally:
                loop.create_datagram_endpoint = original

            return proxy

        proxy = asyncio.run(exercise())
        self.assertEqual(proxy.udpmap, {})
        self.assertEqual(proxy.connections, 0)


if __name__ == "__main__":
    unittest.main()
