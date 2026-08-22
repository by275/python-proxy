import asyncio
import unittest

from pproxy.relay import relay_with_taskgroup


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_runs_both_directions(self):
        completed = []

        async def inbound():
            completed.append("inbound")

        async def outbound():
            completed.append("outbound")

        await relay_with_taskgroup(inbound(), outbound())

        self.assertEqual(set(completed), {"inbound", "outbound"})

    async def test_failure_cancels_the_other_direction(self):
        cancelled = asyncio.Event()

        async def inbound():
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                raise

        async def outbound():
            raise RuntimeError("relay failed")

        with self.assertRaises(ExceptionGroup):
            await relay_with_taskgroup(inbound(), outbound())

        self.assertTrue(cancelled.is_set())


if __name__ == "__main__":
    unittest.main()
