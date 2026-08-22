from . import server
from .config import ProxyConfig
from .errors import ProtocolError

Connection = server.proxies_by_uri
Server = server.proxies_by_uri
Rule = server.compile_rule
DIRECT = server.DIRECT

__all__ = [
    "DIRECT",
    "Connection",
    "ProtocolError",
    "ProxyConfig",
    "Rule",
    "Server",
]
