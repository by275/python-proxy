import argparse
import asyncio
import base64
import contextlib
import os
import pathlib
import statistics
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from pproxy import proto


class DummyAuthTable:
    def authed(self):
        return None

    def set_authed(self, user):
        pass


class DummySock:
    def getsockname(self):
        return ("127.0.0.1", 8080)


class AcceptReader:
    def __init__(self, payload):
        self.payload = payload
        self._buffer = bytearray()

    async def read_until(self, sep):
        return self.payload

    def feed_data(self, data):
        self._buffer.extend(data)


class ChannelReader:
    def __init__(self, payload):
        self.payload = payload
        self.sent = False

    async def read(self, size):
        if self.sent:
            return b""
        self.sent = True
        return self.payload

    async def readuntil(self, sep):
        return b""

    def at_eof(self):
        return self.sent


class DummyWriter:
    def __init__(self):
        self.buffer = bytearray()
        self.closed = False

    def write(self, data):
        self.buffer.extend(data)

    async def drain(self):
        return None

    def is_closing(self):
        return self.closed

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def make_http_request(extra_headers):
    headers = [
        b"GET http://example.com/test?q=1 HTTP/1.1",
        b"Host: example.com",
        b"User-Agent: benchmark-client/1.0",
        b"Accept: */*",
        b"Proxy-Connection: keep-alive",
        b"X-Trace-Id: abcdef123456",
    ]
    headers.extend(extra_headers)
    return b"\r\n".join(headers) + b"\r\n\r\n"


def make_ws_request(extra_headers):
    headers = [
        b"GET /chat HTTP/1.1",
        b"Host: example.com",
        b"Upgrade: websocket",
        b"Connection: Upgrade",
        b"Sec-WebSocket-Key: " + base64.b64encode(os.urandom(16)),
        b"Sec-WebSocket-Protocol: chat",
        b"Sec-WebSocket-Version: 13",
        b"X-Trace-Id: abcdef123456",
    ]
    headers.extend(extra_headers)
    return b"\r\n".join(headers) + b"\r\n\r\n"


async def bench_http_accept(iterations, payload):
    http = proto.HTTP(None)
    times = []
    for _ in range(iterations):
        reader = AcceptReader(payload)
        writer = DummyWriter()
        started = time.perf_counter()
        await http.accept(
            reader,
            None,
            writer,
            authtable=DummyAuthTable(),
            users=None,
            httpget=None,
        )
        times.append(time.perf_counter() - started)
    return times


async def bench_http_channel(iterations, payload):
    http = proto.HTTP(None)
    times = []
    for _ in range(iterations):
        reader = ChannelReader(payload)
        writer = DummyWriter()
        started = time.perf_counter()
        await http.http_channel(reader, writer, lambda *_: None, lambda *_: None)
        times.append(time.perf_counter() - started)
    return times


async def bench_ws_accept(iterations, payload):
    ws = proto.WS(None)
    times = []
    for _ in range(iterations):
        reader = AcceptReader(payload)
        writer = DummyWriter()
        started = time.perf_counter()
        await ws.accept(
            reader,
            None,
            writer,
            users=None,
            authtable=DummyAuthTable(),
            sock=DummySock(),
        )
        times.append(time.perf_counter() - started)
    return times


def summarize(name, values):
    values_us = [value * 1_000_000 for value in values]
    values_us.sort()
    return {
        "name": name,
        "iterations": len(values),
        "avg_us": statistics.mean(values_us),
        "p95_us": values_us[max(0, int(len(values_us) * 0.95) - 1)],
        "ops_per_sec": len(values) / sum(values),
    }


def print_results(results):
    print(
        "case".ljust(14),
        "iters".rjust(8),
        "avg us".rjust(12),
        "p95 us".rjust(12),
        "ops/s".rjust(12),
    )
    for result in results:
        print(
            result["name"].ljust(14),
            str(result["iterations"]).rjust(8),
            f'{result["avg_us"]:.2f}'.rjust(12),
            f'{result["p95_us"]:.2f}'.rjust(12),
            f'{result["ops_per_sec"]:.1f}'.rjust(12),
        )


async def main():
    parser = argparse.ArgumentParser(
        description="Benchmark HTTP and WebSocket header parsing paths."
    )
    parser.add_argument("--iterations", type=int, default=20000)
    parser.add_argument("--extra-headers", type=int, default=20)
    args = parser.parse_args()

    extra_headers = [
        f"X-Bench-{index}: value-{index}".encode()
        for index in range(args.extra_headers)
    ]
    http_payload = make_http_request(extra_headers)
    ws_payload = make_ws_request(extra_headers)

    results = [
        summarize("http_accept", await bench_http_accept(args.iterations, http_payload)),
        summarize("http_channel", await bench_http_channel(args.iterations, http_payload)),
        summarize("ws_accept", await bench_ws_accept(args.iterations, ws_payload)),
    ]
    print_results(results)


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
