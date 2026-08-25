"""Protocol dispatch and URI-scheme registry."""

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .base import Direct
from ..errors import ConnectionClosed, ProtocolError, UnsupportedProtocol
from .http import H2, H3, HTTP, HTTPAdmin, HTTPOnly
from .socks import SS, SSR, Socks4, Socks5, Trojan
from .transparent import Echo, Pf, Redir, SSH, Tunnel
from .websocket import CFP, WS


MAPPINGS = dict(
    direct=Direct,
    http=HTTP,
    httponly=HTTPOnly,
    httpadmin=HTTPAdmin,
    ssh=SSH,
    socks5=Socks5,
    socks4=Socks4,
    socks=Socks5,
    ss=SS,
    ssr=SSR,
    redir=Redir,
    pf=Pf,
    tunnel=Tunnel,
    echo=Echo,
    ws=WS,
    cfp=CFP,
    trojan=Trojan,
    h2=H2,
    h3=H3,
    ssl='',
    secure='',
    insecure='',
    quic='',
)
MAPPINGS['in'] = ''


@dataclass(frozen=True, slots=True)
class ProtocolMetadata:
    """Capability and dependency metadata for one registered scheme."""

    supports_tcp: bool
    supports_udp: bool
    supports_client: bool
    supports_server: bool
    optional_dependency: str | None = None
    default_port: int | None = 8080
    transport_modifier: bool = False


PROTOCOL_METADATA: dict[str, ProtocolMetadata] = {
    'direct': ProtocolMetadata(True, True, True, False, default_port=None),
    'http': ProtocolMetadata(True, False, True, True),
    'httponly': ProtocolMetadata(True, False, True, True),
    'httpadmin': ProtocolMetadata(True, False, True, True),
    'ssh': ProtocolMetadata(True, False, True, False, 'asyncssh', 22),
    'socks5': ProtocolMetadata(True, True, True, True),
    'socks4': ProtocolMetadata(True, False, True, True),
    'socks': ProtocolMetadata(True, True, True, True),
    'ss': ProtocolMetadata(True, True, True, True),
    'ssr': ProtocolMetadata(True, True, True, True),
    'redir': ProtocolMetadata(True, True, False, True),
    'pf': ProtocolMetadata(True, True, False, True),
    'tunnel': ProtocolMetadata(True, True, True, True),
    'echo': ProtocolMetadata(True, True, False, True),
    'ws': ProtocolMetadata(True, False, True, True),
    'cfp': ProtocolMetadata(True, False, True, False, default_port=443),
    'trojan': ProtocolMetadata(True, False, True, True),
    'h2': ProtocolMetadata(True, False, True, True, 'h2'),
    'h3': ProtocolMetadata(False, True, True, True, 'aioquic'),
    'quic': ProtocolMetadata(False, True, True, True, 'aioquic'),
    'ssl': ProtocolMetadata(False, False, False, False, transport_modifier=True),
    'secure': ProtocolMetadata(False, False, False, False, transport_modifier=True),
    'insecure': ProtocolMetadata(False, False, False, False, transport_modifier=True),
    'in': ProtocolMetadata(False, False, False, False, transport_modifier=True),
}


def register_protocol(
    name: str,
    protocol: Any,
    metadata: ProtocolMetadata | None = None,
) -> None:
    """Register an additional scheme without changing the legacy facade.

    Optional protocol adapters can use this hook to add a scheme such as
    ``cfp`` when their separate feature package is enabled. The core package
    intentionally does not enable optional schemes by itself.
    """
    if not name or not isinstance(name, str):
        raise ValueError('protocol name must be a non-empty string')
    MAPPINGS[name] = protocol
    if metadata is not None:
        PROTOCOL_METADATA[name] = metadata


def get_protocol_metadata(name: str) -> ProtocolMetadata | None:
    """Return capability metadata for *name*, if the scheme is registered."""
    return PROTOCOL_METADATA.get(name)


async def accept(protos: Iterable[Any], reader: Any, **kw: Any) -> tuple[Any, ...]:
    """Guess and accept the first configured protocol for a stream."""
    for protocol in protos:
        try:
            user = await protocol.guess(reader, **kw)
        except ProtocolError:
            raise
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as exc:
            raise ConnectionClosed() from exc
        if user:
            ret = await protocol.accept(reader, user, **kw)
            while len(ret) < 4:
                ret += (None,)
            return (protocol,) + ret
    raise UnsupportedProtocol('Unsupported protocol')


def udp_accept(protos: Iterable[Any], data: bytes, **kw: Any) -> tuple[Any, ...]:
    """Accept a datagram with the first configured protocol that matches it."""
    for protocol in protos:
        ret = protocol.udp_accept(data, **kw)
        if ret:
            return (protocol,) + ret
    raise UnsupportedProtocol(f'Unsupported protocol {data[:10]}')


def get_protos(rawprotos: Iterable[str]) -> tuple[str | None, list[Any] | None]:
    """Resolve URI protocol names into configured protocol instances."""
    protos = []
    for value in rawprotos:
        name, _, param = value.partition('{')
        param = param[:-1] if param else None
        protocol = MAPPINGS.get(name)
        if protocol is None:
            return f'existing protocols: {list(MAPPINGS.keys())}', None
        if protocol and protocol not in protos:
            protos.append(protocol(param))
    if not protos:
        return 'no protocol specified', None
    return None, protos
