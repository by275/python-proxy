"""Contract tests for the authenticated worker WebSocket protocol."""

import base64
import hashlib
import re
import unittest

from pproxy import proto, server
from pproxy.errors import ProtocolError


class FakeReader:
    def __init__(self, response_factory):
        self.response_factory = response_factory
        self.received = bytearray()

    async def readuntil(self, _separator):
        return self.response_factory()

    def feed_data(self, data):
        self.received.extend(data)


class FakeWriter:
    def __init__(self):
        self.writes = []
        self.closed = False

    def write(self, data):
        self.writes.append(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    def get_extra_info(self, _key):
        return None


def response_for(
    writer,
    *,
    status=b'HTTP/1.1 101 Switching Protocols',
    extension=None,
    accept=None,
):
    request = writer.writes[0]
    match = re.search(br'^Sec-WebSocket-Key: ([^\r\n]+)', request, re.MULTILINE)
    assert match is not None
    if accept is None:
        accept = base64.b64encode(
            hashlib.sha1(
                match.group(1) + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            ).digest()
        )
    headers = [status, b'Sec-WebSocket-Accept: ' + accept]
    if extension is not None:
        headers.append(b'Sec-WebSocket-Extensions: ' + extension)
    return b'\r\n'.join(headers) + b'\r\n\r\n'


class CFPHandshakeTests(unittest.IsolatedAsyncioTestCase):
    async def connect(self, **response_options):
        writer = FakeWriter()
        reader = FakeReader(lambda: response_for(writer, **response_options))
        protocol = proto.CFP(None)
        await protocol.connect(
            reader,
            writer,
            b'user:secret',
            '2001:db8::20',
            443,
            'worker.example',
        )
        return reader, writer

    async def test_authenticated_targeted_handshake_and_graceful_close(self):
        reader, writer = await self.connect()
        request = writer.writes[0]

        self.assertIn(b'Host: worker.example', request)
        self.assertIn(b'X-Proxy-Target: [2001:db8::20]:443', request)
        self.assertIn(b'Authorization: user:secret', request)
        self.assertNotIn(b'Sec-WebSocket-Extensions:', request)

        writer.write(b'payload')
        frame = writer.writes[-1]
        self.assertEqual(frame[0], 0x82)
        self.assertTrue(frame[1] & 0x80)

        reader.feed_data(b'\x88\x00')
        await writer.graceful_close()
        self.assertTrue(writer.closed)
        close_frame = writer.writes[-1]
        self.assertEqual(close_frame[0], 0x88)
        self.assertTrue(close_frame[1] & 0x80)

    async def test_handshake_rejects_invalid_worker_response(self):
        for options in (
            {'status': b'HTTP/1.1 403 Forbidden'},
            {'accept': b'invalid'},
            {'extension': b'permessage-deflate'},
        ):
            with self.subTest(options=options):
                writer = FakeWriter()
                reader = FakeReader(
                    lambda writer=writer, options=options: response_for(writer, **options)
                )
                with self.assertRaises(ProtocolError):
                    await proto.CFP(None).connect(
                        reader,
                        writer,
                        b'user:secret',
                        'example.test',
                        443,
                        'worker.example',
                    )

    async def test_handshake_rejects_header_injection_values(self):
        writer = FakeWriter()
        reader = FakeReader(lambda: response_for(writer))
        with self.assertRaises(ProtocolError):
            await proto.CFP(None).connect(
                reader,
                writer,
                b'user\r\nX-Injected: yes',
                'example.test',
                443,
                'worker.example',
            )


class CFPFactoryTests(unittest.TestCase):
    def test_cfp_is_a_secure_client_protocol_with_worker_default_port(self):
        option = server.proxies_by_uri('cfp://worker.example/')
        try:
            self.assertEqual(option.rproto.name, 'cfp')
            self.assertEqual(option.port, 443)
            self.assertTrue(proto.get_protocol_metadata('cfp').supports_client)
            self.assertFalse(proto.get_protocol_metadata('cfp').supports_server)
            self.assertEqual(option.sslclient.verify_mode, 2)
        finally:
            option.close()

    def test_cfp_insecure_modifier_is_explicit(self):
        option = server.proxies_by_uri('cfp+insecure://worker.example/')
        try:
            self.assertEqual(option.sslclient.verify_mode, 0)
        finally:
            option.close()


if __name__ == '__main__':
    unittest.main()
