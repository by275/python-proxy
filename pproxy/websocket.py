"""Minimal WebSocket stream framing used by the proxy protocol."""

import os

from . import transport


def xor_mask_bytes(data, mask_key):
    """Apply a WebSocket masking key to *data*."""
    masked = bytearray(data)
    for index, value in enumerate(masked):
        masked[index] = value ^ mask_key[index % 4]
    return bytes(masked)


class WebSocketStream:
    """Adapt a byte stream to binary WebSocket messages."""

    def __init__(self, reader, writer, masked=False):
        self.reader = reader
        self.writer = writer
        self.masked = masked
        self.data_len = None
        self.mask_key = None
        self.opcode = None
        self.buffer = bytearray()
        self.raw_write = writer.write
        self.on_message = reader.feed_data

    def write_frame(self, opcode, payload=b''):
        payload_length = len(payload)
        if payload_length < 126:
            second = bytes([(payload_length | 0x80) if self.masked else payload_length])
        elif payload_length < 65536:
            second = (b'\xfe' if self.masked else b'\x7e') + payload_length.to_bytes(2, 'big')
        else:
            second = (b'\xff' if self.masked else b'\x7f') + payload_length.to_bytes(8, 'big')
        if self.masked:
            mask_key = os.urandom(4)
            payload = xor_mask_bytes(payload, mask_key)
            return self.raw_write(bytes([0x80 | opcode]) + second + mask_key + payload)
        return self.raw_write(bytes([0x80 | opcode]) + second + payload)

    def feed_data(self, data):
        self.buffer.extend(data)
        while True:
            if self.data_len is None:
                if len(self.buffer) < 2:
                    return
                self.opcode = self.buffer[0] & 0x0f
                required = 2 + (4 if self.buffer[1] & 128 else 0)
                payload_marker = self.buffer[1] & 127
                required += 2 if payload_marker == 126 else 8 if payload_marker == 127 else 0
                if len(self.buffer) < required:
                    return
                self.data_len = (
                    int.from_bytes(self.buffer[2:4], 'big')
                    if payload_marker == 126
                    else int.from_bytes(self.buffer[2:10], 'big')
                    if payload_marker == 127
                    else payload_marker
                )
                self.mask_key = self.buffer[required - 4:required] if self.buffer[1] & 128 else None
                del self.buffer[:required]
            else:
                if len(self.buffer) < self.data_len:
                    return
                payload = self.buffer[:self.data_len]
                if self.mask_key:
                    payload = xor_mask_bytes(payload, self.mask_key)
                del self.buffer[:self.data_len]
                self.data_len = None
                if self.opcode == 0x9:
                    self.write_frame(0xA, payload)
                elif self.opcode in (0x8, 0xA):
                    pass
                else:
                    self.on_message(payload)

    def attach(self):
        """Install the adapter on the existing asyncio stream pair."""
        self.reader.feed_data = self.feed_data
        self.writer.write = self.write
        buffered = transport.take_buffer(self.reader)
        if buffered:
            self.feed_data(buffered)
        return self

    def write(self, data):
        if not data:
            return
        return self.write_frame(0x2, data)


def patch_stream(reader, writer, masked=False):
    """Install and return a :class:`WebSocketStream` adapter."""
    return WebSocketStream(reader, writer, masked).attach()
