"""Public compatibility facade for proxy factories and runtime helpers."""

from typing import Any, Callable

from . import server
from .config import ProxyConfig
from .errors import ProtocolError

ProxyFactory = Callable[[str], Any]
RuleFactory = Callable[[str], Callable[[str], Any]]

Connection: ProxyFactory = server.proxies_by_uri
Server: ProxyFactory = server.proxies_by_uri
Rule: RuleFactory = server.compile_rule
DIRECT = server.DIRECT

__all__ = [
    "DIRECT",
    "Connection",
    "ProtocolError",
    "ProxyFactory",
    "ProxyConfig",
    "Rule",
    "RuleFactory",
    "Server",
]
