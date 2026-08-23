"""Exceptions and validation helpers shared by protocol adapters."""


class ConnectionClosed(ConnectionError):
    """Raised when a peer closes before completing a protocol exchange."""

    def __init__(self, message='Connection closed'):
        super().__init__(message)


class ConfigurationError(ValueError):
    """Raised when a proxy URI or runtime option cannot be used."""


class ProtocolError(AssertionError):
    """Raised when an input does not satisfy a protocol contract.

    It remains an ``AssertionError`` subclass for compatibility with callers
    that historically handled failed protocol assertions explicitly.
    """


class AuthenticationError(ProtocolError):
    """Raised when a peer fails protocol authentication."""


class RequestError(ProtocolError):
    """Raised when a peer sends an invalid or unsupported request."""


class UnsupportedProtocol(ProtocolError):
    """Raised when no configured protocol accepts the input."""


class BlockedConnection(ProtocolError):
    """Raised when a configured rule blocks a destination."""


def require(condition, message=""):
    """Raise :class:`ProtocolError` when *condition* is false."""
    if not condition:
        raise ProtocolError(message)
