"""Exceptions and validation helpers shared by protocol adapters."""


class ProtocolError(AssertionError):
    """Raised when an input does not satisfy a protocol contract.

    It remains an ``AssertionError`` subclass for compatibility with callers
    that historically handled failed protocol assertions explicitly.
    """


def require(condition, message=""):
    """Raise :class:`ProtocolError` when *condition* is false."""
    if not condition:
        raise ProtocolError(message)
