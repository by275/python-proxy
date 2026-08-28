"""Benchmark proxy connection setup and relay behavior."""

import argparse
import asyncio
import contextlib
import math
import os
import pathlib
import statistics
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pproxy


async def echo_handler(reader, writer):
    try:
        while not reader.at_eof():
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def start_echo_server():
    server = await asyncio.start_server(echo_handler, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def start_pproxy_server(uri):
    server = pproxy.Server(uri)
    handler = await server.start_server({"rserver": [], "verbose": lambda *_: None})
    port = handler.sockets[0].getsockname()[1]
    return handler, port


async def open_direct_connection(host, port):
    return await asyncio.open_connection(host=host, port=port)


async def open_proxy_connection(proto, proxy_port, host, port):
    conn = pproxy.Connection(f"{proto}://127.0.0.1:{proxy_port}")
    return await conn.tcp_connect(host, port)


async def run_roundtrip(factory, payload, requests_per_worker, warmup):
    reader, writer = await factory()
    durations = []
    try:
        for _ in range(warmup):
            writer.write(payload)
            await writer.drain()
            received = await reader.readexactly(len(payload))
            assert received == payload
        for _ in range(requests_per_worker):
            started = time.perf_counter()
            writer.write(payload)
            await writer.drain()
            received = await reader.readexactly(len(payload))
            ended = time.perf_counter()
            assert received == payload
            durations.append(ended - started)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return durations


async def benchmark_case(name, factory, payload, requests, concurrency, warmup):
    requests_per_worker = math.ceil(requests / concurrency)
    started = time.perf_counter()
    tasks = [
        asyncio.create_task(
            run_roundtrip(factory, payload, requests_per_worker, warmup)
        )
        for _ in range(concurrency)
    ]
    all_durations = []
    for task in tasks:
        all_durations.extend(await task)
    elapsed = time.perf_counter() - started
    total_requests = len(all_durations)
    total_bytes = total_requests * len(payload)
    all_durations.sort()
    p95_index = max(0, math.ceil(total_requests * 0.95) - 1)
    return {
        "name": name,
        "requests": total_requests,
        "payload_bytes": len(payload),
        "elapsed_sec": elapsed,
        "req_per_sec": total_requests / elapsed,
        "mb_per_sec": total_bytes / elapsed / 1024 / 1024,
        "latency_avg_ms": statistics.mean(all_durations) * 1000,
        "latency_p95_ms": all_durations[p95_index] * 1000,
    }


def print_results(results):
    print(
        "case".ljust(10),
        "req".rjust(8),
        "bytes".rjust(10),
        "sec".rjust(8),
        "req/s".rjust(10),
        "MiB/s".rjust(10),
        "avg ms".rjust(10),
        "p95 ms".rjust(10),
    )
    for result in results:
        print(
            result["name"].ljust(10),
            str(result["requests"]).rjust(8),
            str(result["payload_bytes"]).rjust(10),
            f'{result["elapsed_sec"]:.3f}'.rjust(8),
            f'{result["req_per_sec"]:.1f}'.rjust(10),
            f'{result["mb_per_sec"]:.2f}'.rjust(10),
            f'{result["latency_avg_ms"]:.3f}'.rjust(10),
            f'{result["latency_p95_ms"]:.3f}'.rjust(10),
        )


async def main():
    parser = argparse.ArgumentParser(
        description="Benchmark local direct and proxy TCP relay performance."
    )
    parser.add_argument(
        "--protocols",
        nargs="+",
        default=["direct", "http", "socks5"],
        choices=["direct", "http", "socks4", "socks5"],
        help="client transport(s) to benchmark",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=200,
        help="measured roundtrips per case",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=20,
        help="number of concurrent client connections",
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=16 * 1024,
        help="bytes sent and echoed back per roundtrip",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=3,
        help="unmeasured roundtrips per connection before timing",
    )
    args = parser.parse_args()

    payload = os.urandom(args.payload_size)
    echo_server, echo_port = await start_echo_server()
    proxy_servers = {}
    try:
        for proto in args.protocols:
            if proto == "direct":
                continue
            proxy_servers[proto] = await start_pproxy_server(f"{proto}://127.0.0.1:0")

        results = []
        for proto in args.protocols:
            if proto == "direct":
                factory = lambda: open_direct_connection("127.0.0.1", echo_port)
            else:
                proxy_port = proxy_servers[proto][1]
                factory = lambda proto=proto, proxy_port=proxy_port: open_proxy_connection(
                    proto, proxy_port, "127.0.0.1", echo_port
                )
            results.append(
                await benchmark_case(
                    proto,
                    factory,
                    payload,
                    requests=args.requests,
                    concurrency=args.concurrency,
                    warmup=args.warmup,
                )
            )
        print_results(results)
    finally:
        echo_server.close()
        await echo_server.wait_closed()
        for handler, _ in proxy_servers.values():
            handler.close()
            with contextlib.suppress(Exception):
                await handler.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
