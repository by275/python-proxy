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


if __name__ == "__main__":
    unittest.main()
