import asyncio
import unittest

from pproxy import proto


class WebSocketDetectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_guess_peeks_at_a_websocket_request(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n")

        self.assertTrue(await proto.WS(None).guess(reader))
        self.assertEqual(await reader.read(4), b"GET ")


if __name__ == "__main__":
    unittest.main()
