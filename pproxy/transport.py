"""Compatibility helpers for asyncio stream operations."""

import asyncio


DEFAULT_TIMEOUT = 60


async def read(reader, size, timeout=DEFAULT_TIMEOUT):
    """Read up to *size* bytes with the proxy socket timeout."""
    operation = reader.read_w(size) if hasattr(reader, "read_w") else reader.read(size)
    return await asyncio.wait_for(operation, timeout=timeout)


async def read_exactly(reader, size, timeout=DEFAULT_TIMEOUT):
    """Read exactly *size* bytes with the proxy socket timeout."""
    operation = (
        reader.read_n(size)
        if hasattr(reader, "read_n")
        else reader.readexactly(size)
    )
    return await asyncio.wait_for(operation, timeout=timeout)


async def read_until(reader, separator, timeout=DEFAULT_TIMEOUT):
    """Read through *separator* with the proxy socket timeout."""
    operation = (
        reader.read_until(separator)
        if hasattr(reader, "read_until")
        else reader.readuntil(separator)
    )
    return await asyncio.wait_for(operation, timeout=timeout)


def rollback(reader, data):
    """Put already-read bytes back in front of a stream."""
    method = getattr(reader, "rollback", None)
    if method is not None:
        method(data)
        return

    buffer = getattr(reader, "_buffer", None)
    if buffer is None:
        raise TypeError(f"{type(reader).__name__} does not support rollback")
    buffer[:0] = data


def prepend(reader, data):
    """Prepend bytes to a stream's pending input."""
    if not data:
        return
    method = getattr(reader, "prepend_data", None)
    if method is not None:
        method(data)
        return
    rollback(reader, data)


def take_buffer(reader):
    """Take bytes already buffered by a stream without exposing its storage."""
    method = getattr(reader, "take_buffer", None)
    if method is not None:
        return method()

    buffer = getattr(reader, "_buffer", None)
    if not buffer:
        return b""
    reader._buffer = bytearray()
    return bytes(buffer)
