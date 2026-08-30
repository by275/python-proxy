"""Measure proxy connection setup latency on loopback transports."""

import argparse
import asyncio
import contextlib
import pathlib
import statistics
import sys
import time

script_path = pathlib.Path(__file__).resolve()
sys.path.insert(0, str(script_path.parent))
sys.path.insert(0, str(script_path.parents[1]))

from benchmark_proxy import (  # noqa: E402  # pylint: disable=wrong-import-position
    open_proxy_connection,
    start_echo_server,
    start_pproxy_server,
)


async def benchmark_setup(proto, proxy_port, echo_port, connections):
    """Measure setup latency for repeated connections to one proxy."""
    durations = []
    for _ in range(connections):
        started = time.perf_counter()
        _reader, writer = await open_proxy_connection(proto, proxy_port, "127.0.0.1", echo_port)
        durations.append(time.perf_counter() - started)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    durations.sort()
    p95_index = max(0, int(len(durations) * 0.95) - 1)
    return {
        "protocol": proto,
        "connections": len(durations),
        "average_ms": statistics.mean(durations) * 1000,
        "p95_ms": durations[p95_index] * 1000,
        "connections_per_sec": len(durations) / sum(durations),
    }


async def main():
    """Run setup benchmarks for the requested protocols."""
    parser = argparse.ArgumentParser(description="Benchmark proxy connection setup latency.")
    parser.add_argument("--protocols", nargs="+", default=["http", "socks5"])
    parser.add_argument("--connections", type=int, default=100)
    args = parser.parse_args()

    echo_server, echo_port = await start_echo_server()
    proxy_servers = {}
    try:
        for proto in args.protocols:
            proxy_servers[proto] = await start_pproxy_server(f"{proto}://127.0.0.1:0")
        print("protocol connections average_ms p95_ms connections_per_sec")
        for proto in args.protocols:
            handler, proxy_port = proxy_servers[proto]
            result = await benchmark_setup(proto, proxy_port, echo_port, args.connections)
            print(
                result["protocol"],
                result["connections"],
                f'{result["average_ms"]:.3f}',
                f'{result["p95_ms"]:.3f}',
                f'{result["connections_per_sec"]:.1f}',
            )
    finally:
        echo_server.close()
        await echo_server.wait_closed()
        for handler, _ in proxy_servers.values():
            handler.close()
            with contextlib.suppress(Exception):
                await handler.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
