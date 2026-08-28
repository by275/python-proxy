"""Test the WebSocket stream adapter and frame helpers."""

import unittest

from pproxy.errors import ProtocolError
from pproxy.websocket import WebSocketStream, xor_mask_bytes


class WebSocketAdapterTests(unittest.TestCase):
    def test_mask_helper_round_trip(self):
        payload = b'websocket payload'
        mask = b'abcd'
        self.assertEqual(xor_mask_bytes(xor_mask_bytes(payload, mask), mask), payload)

    def test_adapter_is_returned_after_attach(self):
        class Reader:
            def __init__(self):
                self.buffer = bytearray()

            def feed_data(self, data):
                self.buffer.extend(data)

        class Writer:
            def __init__(self):
                self.writes = []

            def write(self, data):
                self.writes.append(data)

        reader, writer = Reader(), Writer()
        adapter = WebSocketStream(reader, writer).attach()

        self.assertIsInstance(adapter, WebSocketStream)
        reader.feed_data(b'\x81\x02ok')
        self.assertEqual(reader.buffer, bytearray(b'ok'))
        writer.write(b'reply')
        self.assertEqual(writer.writes, [b'\x82\x05reply'])

    def test_server_side_adapter_rejects_unmasked_input(self):
        class Reader:
            def feed_data(self, _data):
                return None

        class Writer:
            def __init__(self):
                self.closed = False

            def write(self, _data):
                return None

            def close(self):
                self.closed = True

        reader, writer = Reader(), Writer()
        _adapter = WebSocketStream(reader, writer, expect_masked=True).attach()

        with self.assertRaises(ProtocolError):
            reader.feed_data(b'\x81\x02ok')
        self.assertTrue(writer.closed)


if __name__ == "__main__":
    unittest.main()
