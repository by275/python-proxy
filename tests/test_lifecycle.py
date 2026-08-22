import asyncio
import unittest

from pproxy import server


class BackwardLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_close_cancels_background_tasks(self):
        backward = object.__new__(server.ProxyBackward)
        backward.closed = False
        backward.tasks = set()
        backward.writers = set()

        task = asyncio.create_task(asyncio.Event().wait())
        backward.tasks.add(task)
        backward.close()

        await asyncio.sleep(0)
        self.assertTrue(task.cancelled())
        self.assertTrue(backward.closed)

    def test_udp_discard_releases_connection_accounting(self):
        proxy = server.ProxyDirect()
        addr = ("127.0.0.1", 53)
        protocol = object()
        proxy.connection_change(1)
        proxy.udp_touch(addr, protocol)

        self.assertIs(proxy.udp_discard(addr), protocol)
        self.assertEqual(proxy.connections, 0)
        self.assertNotIn(addr, proxy.udpmap)


if __name__ == "__main__":
    unittest.main()
