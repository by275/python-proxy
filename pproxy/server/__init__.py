"""Compatibility facade for server construction and runtime helpers."""

from .. import admin, proto, relay, transport
from ..config import ProxyConfig
from ..errors import (
    BlockedConnection,
    ConfigurationError,
    ConnectionClosed,
    ProtocolError,
    UpstreamError,
    require,
)
from ..runtime import (
    DEFAULT_LISTENER_URI,
    TaskRegistry,
    UDP_LIMIT,
    UDP_TASK_LIMIT,
    is_unauthenticated_wildcard,
)
from ..__doc__ import *

from .common import (
    DUMMY,
    SOCKET_TIMEOUT,
    AuthTable,
    compile_rule,
    prepare_ciphers,
    schedule,
    split_uri_jumps,
)
from .connections import (
    DIRECT,
    ProxyBackward,
    ProxyDirect,
    ProxySimple,
    check_server_alive,
)
from .diagnostics import print_server_started, test_url
from .factory import proxy_by_uri, proxies_by_uri, sslcontexts
from .handlers import datagram_handler, stream_handler

relay_with_taskgroup = relay.relay_with_taskgroup


def main(args=None):
    """Compatibility wrapper for the command-line application."""
    from ..app import main as app_main

    return app_main(args)


# Optional adapters remain available through their historical server aliases.
from ..h2 import ProxyH2
from ..quic import ProxyH3, ProxyQUIC
from ..ssh import ProxySSH
