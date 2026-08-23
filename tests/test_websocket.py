import asyncio
import unittest

from pproxy import proto


class WebSocketDetectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_guess_peeks_at_a_websocket_request(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n")

        self.assertTrue(await proto.WS(None).guess(reader))
        self.assertEqual(await reader.read(4), b"GET ")


class BufferedReader:
    def __init__(self):
        self._buffer = bytearray()

    def feed_data(self, data):
        self._buffer.extend(data)


class CaptureWriter:
    def __init__(self):
        self.writes = []

    def write(self, data):
        self.writes.append(data)


class WebSocketFrameTests(unittest.TestCase):
    def test_fragmented_masked_frame_and_binary_write(self):
        reader = BufferedReader()
        writer = CaptureWriter()
        received = []
        reader.feed_data = received.append
        proto.WS(None).patch_ws_stream(reader, writer)

        payload = b"hello"
        mask = b"abcd"
        frame = b"\x81" + bytes([0x80 | len(payload)]) + mask + proto.xor_mask_bytes(payload, mask)
        reader.feed_data(frame[:3])
        reader.feed_data(frame[3:])

        self.assertEqual(received, [payload])
        writer.write(b"reply")
        self.assertEqual(writer.writes[-1], b"\x82\x05reply")

    def test_ping_is_answered_and_extended_payload_length_is_encoded(self):
        reader = BufferedReader()
        writer = CaptureWriter()
        proto.WS(None).patch_ws_stream(reader, writer)

        mask = b"abcd"
        reader.feed_data(b"\x89\x84" + mask + proto.xor_mask_bytes(b"ping", mask))
        self.assertEqual(writer.writes, [b"\x8a\x04ping"])

        payload = b"x" * 126
        writer.write(payload)
        self.assertEqual(writer.writes[-1][:4], b"\x82~\x00\x7e")
        self.assertEqual(writer.writes[-1][4:], payload)


if __name__ == "__main__":
    unittest.main()
