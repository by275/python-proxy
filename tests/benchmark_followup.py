"""Measure connection setup costs that are candidates for later optimization.

The proxy loopback benchmark remains the compatibility gate. This script measures
individual setup operations so that a faster-looking refactor can be checked against
the cost it is intended to remove. It requires the development ``pyperf`` extra.
"""

import asyncio
import pathlib
import sys
import time

import pyperf

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from pproxy import server
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


def time_statistics_callbacks(loops):
    def modstat(user, remote_ip, host):
        def update(amount):
            return None

        return update

    started = time.perf_counter()
    for _ in range(loops):
        metric = modstat(None, "127.0.0.1", "example.com")
        metric(4096)
        metric(-1)
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
    runner.bench_time_func("statistics_callbacks", time_statistics_callbacks)


if __name__ == "__main__":
    main()
