import asyncio
import unittest

from pproxy import transport


class FakeReader:
    def __init__(self):
        self.calls = []

    async def read(self, size):
        self.calls.append(("read", size))
        return b"data"

    async def readexactly(self, size):
        self.calls.append(("readexactly", size))
        return b"x" * size

    async def readuntil(self, separator):
        self.calls.append(("readuntil", separator))
        return b"header" + separator


class LegacyTimedReader:
    def __init__(self):
        self.calls = []

    async def read_w(self, size):
        self.calls.append(("read_w", size))
        return b"data"

    async def read_n(self, size):
        self.calls.append(("read_n", size))
        return b"x" * size

    async def read_until(self, separator):
        self.calls.append(("read_until", separator))
        return separator


class TransportHelperTests(unittest.IsolatedAsyncioTestCase):
    async def test_delegates_to_standard_stream_methods(self):
        reader = FakeReader()

        self.assertEqual(await transport.read(reader, 4), b"data")
        self.assertEqual(await transport.read_exactly(reader, 3), b"xxx")
        self.assertEqual(await transport.read_until(reader, b"\r\n"), b"header\r\n")
        self.assertEqual(
            reader.calls,
            [("read", 4), ("readexactly", 3), ("readuntil", b"\r\n")],
        )

    async def test_rollback_uses_a_stream_reader_buffer(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET / HTTP/1.1")

        data = await transport.read(reader, 4)
        transport.rollback(reader, data)

        self.assertEqual(await reader.read(4), b"GET ")

    async def test_legacy_timed_methods_are_not_double_wrapped(self):
        reader = LegacyTimedReader()

        self.assertEqual(await transport.read(reader, 4), b"data")
        self.assertEqual(await transport.read_exactly(reader, 3), b"xxx")
        self.assertEqual(await transport.read_until(reader, b"\r\n"), b"\r\n")
        self.assertEqual(
            reader.calls,
            [("read_w", 4), ("read_n", 3), ("read_until", b"\r\n")],
        )

    async def test_prepend_and_take_buffer_use_public_helpers(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"body")

        self.assertEqual(transport.take_buffer(reader), b"body")
        transport.prepend(reader, b"head")

        self.assertEqual(await reader.read(4), b"head")
