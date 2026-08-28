"""Measure connection setup costs that are candidates for later optimization.

The proxy loopback benchmark remains the compatibility gate. This script measures
individual setup operations so that a faster-looking refactor can be checked against
the cost it is intended to remove. It requires the development ``pyperf`` extra.
"""

import asyncio
import importlib.util
import io
import pathlib
import sys
import time

import pyperf

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from pproxy import cipher as cipher_runtime
from pproxy import server
from pproxy import websocket as websocket_runtime
from pproxy.cipher import PacketCipher
from pproxy.cipherpy import MAP as pure_cipher_map
from pproxy.protocols import http, socks, websocket
from pproxy.runtime import TaskRegistry


class ProbeReader:
    """Small reader with the same rollback surface used by protocol guessing."""

    def __init__(self, payload):
        self.payload = payload
        self._buffer = bytearray()

    async def read(self, size):
        return self.payload[:size]


def time_argument_expansion(loops):
    proxy = server.proxies_by_uri("http://127.0.0.1:0")
    args = {"rserver": [], "verbose": server.DUMMY, "ruport": False}
    started = time.perf_counter()
    for _ in range(loops):
        result = {**vars(proxy), **args}
        if result["protos"] is not proxy.protos:
            raise AssertionError("argument expansion changed the protocol list")
    return time.perf_counter() - started


def time_argument_expansion_from_cached_mapping(loops):
    proxy = server.proxies_by_uri("http://127.0.0.1:0")
    proxy_values = vars(proxy)
    args = {"rserver": [], "verbose": server.DUMMY, "ruport": False}
    started = time.perf_counter()
    for _ in range(loops):
        result = {**proxy_values, **args}
        if result["protos"] is not proxy.protos:
            raise AssertionError("argument expansion changed the protocol list")
    return time.perf_counter() - started


async def guess_protocols(protocols, payload):
    for protocol in protocols:
        reader = ProbeReader(payload)
        if await protocol.guess(reader):
            return protocol
    return None


def time_protocol_guess(loops, protocol_count):
    protocol_sets = {
        1: (socks.Socks5,),
        2: (http.HTTP, socks.Socks5),
        4: (http.HTTP, websocket.WS, socks.Socks4, socks.Socks5),
    }
    protocol_types = protocol_sets[protocol_count]
    protocols = [protocol_type(None) for protocol_type in protocol_types[:protocol_count]]
    loop = asyncio.new_event_loop()
    started = time.perf_counter()

    async def run():
        for _ in range(loops):
            if await guess_protocols(protocols, b"\x05") is not protocols[-1]:
                raise AssertionError("protocol probe did not reach the expected protocol")

    try:
        loop.run_until_complete(run())
    finally:
        loop.close()
    return time.perf_counter() - started


def time_task_creation(loops):
    loop = asyncio.new_event_loop()
    started = time.perf_counter()

    async def run():
        tasks = [asyncio.create_task(asyncio.sleep(0)) for _ in range(loops)]
        await asyncio.gather(*tasks)

    try:
        loop.run_until_complete(run())
    finally:
        loop.close()
    return time.perf_counter() - started


def time_registry_task_creation(loops):
    loop = asyncio.new_event_loop()
    registry_owner = TaskRegistry()
    started = time.perf_counter()

    async def run():
        tasks = [registry_owner.create_task(asyncio.sleep(0)) for _ in range(loops)]
        await asyncio.gather(*tasks)
        await asyncio.sleep(0)

    try:
        loop.run_until_complete(run())
    finally:
        loop.close()
    return time.perf_counter() - started


def time_task_group(loops):
    loop = asyncio.new_event_loop()
    started = time.perf_counter()

    async def run():
        for _ in range(loops):
            async with asyncio.TaskGroup() as task_group:
                task_group.create_task(asyncio.sleep(0))

    try:
        loop.run_until_complete(run())
    finally:
        loop.close()
    return time.perf_counter() - started


def time_task_group_cancellation(loops):
    loop = asyncio.new_event_loop()
    started = time.perf_counter()

    async def fail_group():
        async def fail():
            raise RuntimeError("benchmark cancellation")

        try:
            async with asyncio.TaskGroup() as task_group:
                task_group.create_task(asyncio.Event().wait())
                task_group.create_task(fail())
        except* RuntimeError:
            pass

    async def run():
        for _ in range(loops):
            await fail_group()

    try:
        loop.run_until_complete(run())
    finally:
        loop.close()
    return time.perf_counter() - started


def time_statistics_callbacks(loops):
    def modstat(_user, _remote_ip, _host):
        def update(_amount):
            return None

        return update

    started = time.perf_counter()
    for _ in range(loops):
        metric = modstat(None, "127.0.0.1", "example.com")
        metric(4096)
        metric(-1)
    return time.perf_counter() - started


def time_http_header_parsing(loops):
    request = (
        b"GET http://example.com/path?q=1 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: benchmark\r\n"
        b"Accept: */*\r\n"
        b"X-Trace-Id: abcdef\r\n\r\n"
    )
    started = time.perf_counter()
    for _ in range(loops):
        result = http.parse_http_request_head(request[:-4])
        if result[4] != "example.com":
            raise AssertionError("HTTP parser returned the wrong host")
    return time.perf_counter() - started


class MessageReader:
    def __init__(self):
        self.messages = 0

    def feed_data(self, _data):
        self.messages += 1


class MessageWriter:
    def write(self, _data):
        return None


def time_websocket_frame_parsing(loops):
    reader = MessageReader()
    stream = websocket_runtime.WebSocketStream(reader, MessageWriter())
    payload = b"proxy websocket payload"
    frame = bytes((0x82, len(payload))) + payload
    started = time.perf_counter()
    for _ in range(loops):
        stream.feed_data(frame)
    if reader.messages != loops:
        raise AssertionError("WebSocket parser lost a message")
    return time.perf_counter() - started


def time_socks_address_parsing(loops):
    address = b"\x0bexample.com" + (443).to_bytes(2, "big")
    started = time.perf_counter()
    for _ in range(loops):
        host_name, port = socks.socks_address(io.BytesIO(address), 3)
        if (host_name, port) != ("example.com", 443):
            raise AssertionError("SOCKS address parser returned the wrong address")
    return time.perf_counter() - started


def time_udp_bookkeeping(loops):
    proxy = server.ProxyDirect()
    protocol = type("Protocol", (), {"transport": None})()
    started = time.perf_counter()
    for index in range(loops):
        proxy.udp_touch(("127.0.0.1", index % 32), protocol)
        proxy.udp_evict_if_needed()
    return time.perf_counter() - started


def time_pure_python_cipher_packet(loops):
    cipher_class = pure_cipher_map["chacha20"]
    packet_cipher = PacketCipher(cipher_class, b"benchmark-key", "chacha20")
    payload = b"x" * 256
    started = time.perf_counter()
    for _ in range(loops):
        if not packet_cipher.encrypt(payload):
            raise AssertionError("cipher returned an empty packet")
    return time.perf_counter() - started


def time_accelerated_cipher_packet(loops):
    cipher_class = cipher_runtime.MAP.get("chacha20")
    if cipher_class is None:
        return 0.0
    packet_cipher = PacketCipher(cipher_class, b"benchmark-key", "chacha20")
    payload = b"x" * 256
    started = time.perf_counter()
    for _ in range(loops):
        if not packet_cipher.encrypt(payload):
            raise AssertionError("cipher returned an empty packet")
    return time.perf_counter() - started


def main():
    runner = pyperf.Runner()
    runner.bench_time_func("connection_vars_kwargs", time_argument_expansion)
    runner.bench_time_func("connection_cached_mapping", time_argument_expansion_from_cached_mapping)
    for protocol_count in (1, 2, 4):
        runner.bench_time_func(
            f"protocol_guess_{protocol_count}",
            time_protocol_guess,
            protocol_count,
        )
    runner.bench_time_func("task_creation", time_task_creation)
    runner.bench_time_func("task_registry_creation", time_registry_task_creation)
    runner.bench_time_func("task_group_creation", time_task_group)
    runner.bench_time_func("task_group_cancellation", time_task_group_cancellation)
    runner.bench_time_func("statistics_callbacks", time_statistics_callbacks)
    runner.bench_time_func("http_header_parsing", time_http_header_parsing)
    runner.bench_time_func("websocket_frame_parsing", time_websocket_frame_parsing)
    runner.bench_time_func("socks_address_parsing", time_socks_address_parsing)
    runner.bench_time_func("udp_bookkeeping", time_udp_bookkeeping)
    runner.bench_time_func("pure_python_cipher_packet", time_pure_python_cipher_packet)
    if importlib.util.find_spec("Crypto") and "chacha20" in cipher_runtime.MAP:
        runner.bench_time_func("accelerated_cipher_packet", time_accelerated_cipher_packet)


if __name__ == "__main__":
    main()
