"""Typed internal configuration used when constructing proxy backends."""

from dataclasses import dataclass, fields
from typing import Any


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    """Configuration shared by the proxy implementations."""

    jump: Any
    protos: Any
    cipher: Any
    users: Any
    rule: Any
    bind: Any
    host_name: Any
    port: Any
    unix: bool
    lbind: Any
    sslclient: Any
    sslserver: Any

    def as_kwargs(self):
        """Return constructor arguments without exposing dataclass internals."""
        return {field.name: getattr(self, field.name) for field in fields(self)}
