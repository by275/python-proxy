"""Compatibility facade for stream transport helpers."""

from .streams import (
    DEFAULT_TIMEOUT,
    close_writer,
    prepend,
    read,
    read_exactly,
    read_until,
    rollback,
    take_buffer,
)

__all__ = [
    "DEFAULT_TIMEOUT",
    "close_writer",
    "prepend",
    "read",
    "read_exactly",
    "read_until",
    "rollback",
    "take_buffer",
]
