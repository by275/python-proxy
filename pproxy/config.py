"""Typed internal configuration used when constructing proxy backends."""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from typing import Any


def netloc_split(
    loc: str,
    default_host: str | None = None,
    default_port: int | None = None,
) -> tuple[str | None, int | None]:
    """Split a host:port netloc while preserving bracketed IPv6 syntax."""
    ipv6 = re.fullmatch(r'\[([0-9a-fA-F:]*)\](?::(\d+)?)?', loc)
    if ipv6:
        host_name, port = ipv6.groups()
    elif ':' in loc:
        host_name, port = loc.rsplit(':', 1)
    else:
        host_name, port = loc, None
    return host_name or default_host, int(port) if port else default_port


@dataclass(frozen=True, slots=True)
class ProxyConfig:  # pylint: disable=too-many-instance-attributes
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
    insecure_host_key: bool = False

    def as_kwargs(self) -> dict[str, Any]:
        """Return constructor arguments without exposing dataclass internals."""
        return {field.name: getattr(self, field.name) for field in fields(self)}
