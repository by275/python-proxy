"""Test TLS stream setup and certificate handling."""

import asyncio
import unittest

from pproxy import tls


class TLSAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_without_context_preserves_stream_pair(self):
        reader = asyncio.StreamReader()
        writer = object()

        self.assertEqual(tls.wrap(reader, writer, None), (reader, writer))


if __name__ == "__main__":
    unittest.main()
