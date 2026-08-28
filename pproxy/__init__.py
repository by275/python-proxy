"""Public compatibility facade for proxy factories and runtime helpers."""

from typing import Any, Callable

from . import server
from .config import ProxyConfig
from .errors import (
    AuthenticationError,
    BlockedConnection,
    ConfigurationError,
    ConnectionClosed,
    ProtocolError,
    RequestError,
    UpstreamError,
    UnsupportedProtocol,
)

ProxyFactory = Callable[[str], Any]
RuleFactory = Callable[[str], Callable[[str], Any]]

# These capitalized aliases are part of the historical public facade.
Connection: ProxyFactory = server.proxies_by_uri  # pylint: disable=invalid-name
Server: ProxyFactory = server.proxies_by_uri  # pylint: disable=invalid-name
Rule: RuleFactory = server.compile_rule  # pylint: disable=invalid-name
DIRECT = server.DIRECT

__all__ = [
    "DIRECT",
    "AuthenticationError",
    "BlockedConnection",
    "ConfigurationError",
    "ConnectionClosed",
    "Connection",
    "ProtocolError",
    "ProxyFactory",
    "ProxyConfig",
    "Rule",
    "RuleFactory",
    "Server",
    "RequestError",
    "UpstreamError",
    "UnsupportedProtocol",
]
