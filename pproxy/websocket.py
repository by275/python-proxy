"""Minimal WebSocket stream framing used by the proxy protocol."""

import os

from . import transport
from .errors import ProtocolError
from .runtime import WEBSOCKET_FRAME_LIMIT, WEBSOCKET_MESSAGE_LIMIT

MAX_FRAME_SIZE = WEBSOCKET_FRAME_LIMIT
MAX_MESSAGE_SIZE = WEBSOCKET_MESSAGE_LIMIT


def xor_mask_bytes(data, mask_key):
    """Apply a WebSocket masking key to *data*."""
    masked = bytearray(data)
    for index, value in enumerate(masked):
        masked[index] = value ^ mask_key[index % 4]
    return bytes(masked)


class WebSocketStream:  # pylint: disable=too-many-instance-attributes
    """Adapt a byte stream to bounded binary WebSocket messages."""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        reader,
        writer,
        masked=False,
        *,
        expect_masked=False,
        max_frame_size=MAX_FRAME_SIZE,
        max_message_size=MAX_MESSAGE_SIZE,
        on_close=None,
    ):
        self.reader = reader
        self.writer = writer
        self.masked = masked
        self.expect_masked = expect_masked
        self.max_frame_size = max_frame_size
        self.max_message_size = max_message_size
        self.data_len = None
        self.mask_key = None
        self.opcode = None
        self.fin = False
        self.buffer = bytearray()
        self.message_opcode = None
        self.message_buffer = bytearray()
        self.raw_write = writer.write
        self.on_message = reader.feed_data
        self.on_close = on_close
        self.closed = False
        self.close_sent = False

    def _fail(self, message):
        """Close the stream and raise a protocol error for invalid input."""
        self.closed = True
        close = getattr(self.writer, 'close', None)
        if close is not None:
            close()
        raise ProtocolError(message)

    def write_frame(self, opcode, payload=b''):
        """Encode and write one bounded WebSocket frame."""
        payload_length = len(payload)
        if payload_length > self.max_frame_size:
            raise ProtocolError('WebSocket frame exceeds configured limit')
        if opcode >= 8 and (payload_length > 125 or opcode not in (8, 9, 10)):
            raise ProtocolError('invalid WebSocket control frame')
        if opcode == 8:
            self.close_sent = True
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

    def _emit_message(self, payload):
        """Append a frame payload and emit a completed message."""
        if len(self.message_buffer) + len(payload) > self.max_message_size:
            self._fail('WebSocket message exceeds configured limit')
        self.message_buffer.extend(payload)
        if self.fin:
            message = bytes(self.message_buffer)
            self.message_buffer.clear()
            self.message_opcode = None
            self.on_message(message)

    def _handle_frame(self, payload):
        """Dispatch a decoded frame to data, control, or close handling."""
        if self.opcode == 0:
            if self.message_opcode is None:
                self._fail('unexpected WebSocket continuation frame')
            self._emit_message(payload)
        elif self.opcode in (1, 2):
            if self.message_opcode is not None:
                self._fail('new WebSocket data frame before continuation completed')
            self.message_opcode = self.opcode
            self._emit_message(payload)
        elif self.opcode == 9:
            self.write_frame(10, payload)
        elif self.opcode == 8:
            if not self.close_sent:
                self.write_frame(8, payload)
            self.closed = True
            if self.on_close is not None:
                self.on_close(payload)
        elif self.opcode == 10:
            return
        else:
            self._fail('unknown WebSocket opcode')

    def feed_data(self, data):  # pylint: disable=too-many-branches
        """Decode as many complete WebSocket frames as the buffer contains."""
        if self.closed:
            return
        self.buffer.extend(data)
        while True:
            if self.data_len is None:
                if len(self.buffer) < 2:
                    return
                first, second = self.buffer[:2]
                self.fin = bool(first & 0x80)
                if first & 0x70:
                    self._fail('reserved WebSocket bits are not supported')
                self.opcode = first & 0x0f
                is_masked = bool(second & 0x80)
                if is_masked != self.expect_masked:
                    self._fail('unexpected WebSocket masking state')
                payload_marker = second & 0x7f
                extension_size = 2 if payload_marker == 126 else 8 if payload_marker == 127 else 0
                header_size = 2 + extension_size + (4 if is_masked else 0)
                if len(self.buffer) < header_size:
                    return
                if payload_marker == 126:
                    payload_length = int.from_bytes(self.buffer[2:4], 'big')
                elif payload_marker == 127:
                    payload_length = int.from_bytes(self.buffer[2:10], 'big')
                    if payload_length & (1 << 63):
                        self._fail('invalid WebSocket payload length')
                else:
                    payload_length = payload_marker
                if self.opcode >= 8 and (not self.fin or payload_length > 125):
                    self._fail('invalid WebSocket control frame')
                if payload_length > self.max_frame_size:
                    self._fail('WebSocket frame exceeds configured limit')
                self.mask_key = self.buffer[header_size - 4:header_size] if is_masked else None
                self.data_len = payload_length
                del self.buffer[:header_size]
            if len(self.buffer) < self.data_len:
                return
            payload = self.buffer[:self.data_len]
            if self.mask_key:
                payload = xor_mask_bytes(payload, self.mask_key)
            del self.buffer[:self.data_len]
            self.data_len = None
            self._handle_frame(payload)

    def attach(self):
        """Install the adapter on the existing asyncio stream pair."""
        self.reader.feed_data = self.feed_data
        self.writer.write = self.write
        buffered = transport.take_buffer(self.reader)
        if buffered:
            self.feed_data(buffered)
        return self

    def write(self, data):
        """Write application data as one binary WebSocket message."""
        if not data:
            return None
        return self.write_frame(2, data)


def patch_stream(reader, writer, masked=False, *, on_close=None):
    """Install and return a :class:`WebSocketStream` adapter."""
    return WebSocketStream(
        reader,
        writer,
        masked,
        expect_masked=not masked,
        on_close=on_close,
    ).attach()
