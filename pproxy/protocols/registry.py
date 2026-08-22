"""Protocol dispatch and URI-scheme registry."""

from .base import Direct
from .http import H2, H3, HTTP, HTTPAdmin, HTTPOnly
from .socks import SS, SSR, Socks4, Socks5, Trojan
from .transparent import Echo, Pf, Redir, SSH, Tunnel
from .websocket import WS


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
    trojan=Trojan,
    h2=H2,
    h3=H3,
    ssl='',
    secure='',
    quic='',
)
MAPPINGS['in'] = ''


def register_protocol(name, protocol):
    """Register an additional scheme without changing the legacy facade.

    Optional protocol adapters can use this hook to add a scheme such as
    ``cfp`` when their separate feature package is enabled. The core package
    intentionally does not enable optional schemes by itself.
    """
    if not name or not isinstance(name, str):
        raise ValueError('protocol name must be a non-empty string')
    MAPPINGS[name] = protocol


async def accept(protos, reader, **kw):
    for protocol in protos:
        try:
            user = await protocol.guess(reader, **kw)
        except Exception:
            raise Exception('Connection closed')
        if user:
            ret = await protocol.accept(reader, user, **kw)
            while len(ret) < 4:
                ret += (None,)
            return (protocol,) + ret
    raise Exception('Unsupported protocol')


def udp_accept(protos, data, **kw):
    for protocol in protos:
        ret = protocol.udp_accept(data, **kw)
        if ret:
            return (protocol,) + ret
    raise Exception(f'Unsupported protocol {data[:10]}')


def get_protos(rawprotos):
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
