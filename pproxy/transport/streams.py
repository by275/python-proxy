"""Compatibility helpers for asyncio stream operations."""

import asyncio
from typing import Any

DEFAULT_TIMEOUT = 60


async def read(reader: Any, size: int, timeout: float | None = DEFAULT_TIMEOUT) -> bytes:
    """Read up to *size* bytes with the proxy socket timeout."""
    if hasattr(reader, "read_w"):
        operation = reader.read_w(size)
    else:
        operation = reader.read(size)
    if timeout is None:
        return await operation
    return await asyncio.wait_for(operation, timeout=timeout)


async def read_exactly(reader: Any, size: int, timeout: float | None = DEFAULT_TIMEOUT) -> bytes:
    """Read exactly *size* bytes with the proxy socket timeout."""
    if hasattr(reader, "read_n"):
        return await reader.read_n(size)
    operation = reader.readexactly(size)
    return await asyncio.wait_for(operation, timeout=timeout)


async def read_until(
    reader: Any,
    separator: bytes,
    timeout: float | None = DEFAULT_TIMEOUT,
    limit: int | None = None,
) -> bytes:
    """Read through *separator* with the proxy socket timeout."""
    if hasattr(reader, "read_until"):
        result = await reader.read_until(separator)
    else:
        operation = reader.readuntil(separator)
        result = await asyncio.wait_for(operation, timeout=timeout)
    if limit is not None and len(result) > limit:
        raise ValueError(f"stream data exceeds limit of {limit} bytes")
    return result


def rollback(reader: Any, data: bytes) -> None:
    """Put already-read bytes back in front of a stream."""
    method = getattr(reader, "rollback", None)
    if method is not None:
        method(data)
        return

    buffer = getattr(reader, "_buffer", None)
    if buffer is None:
        raise TypeError(f"{type(reader).__name__} does not support rollback")
    buffer[:0] = data


def prepend(reader: Any, data: bytes) -> None:
    """Prepend bytes to a stream's pending input."""
    if not data:
        return
    method = getattr(reader, "prepend_data", None)
    if method is not None:
        method(data)
        return
    rollback(reader, data)


def take_buffer(reader: Any) -> bytes:
    """Take bytes already buffered by a stream without exposing its storage."""
    method = getattr(reader, "take_buffer", None)
    if method is not None:
        return method()

    buffer = getattr(reader, "_buffer", None)
    if not buffer:
        return b""
    reader._buffer = bytearray()
    return bytes(buffer)
