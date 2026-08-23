"""Shared runtime safety and resource policies."""

from typing import Any

DEFAULT_LISTENER_URI = 'http+socks4+socks5://127.0.0.1:8080/'
UDP_LIMIT = 30
UDP_TASK_LIMIT = 256
HTTP_HEADER_LIMIT = 32 * 1024
ADMIN_BODY_LIMIT = 64 * 1024
WEBSOCKET_FRAME_LIMIT = 16 * 1024 * 1024
WEBSOCKET_MESSAGE_LIMIT = 16 * 1024 * 1024
H2_STREAM_LIMIT = 1024


def is_unauthenticated_wildcard(option: Any) -> bool:
    """Return whether a listener can accept unauthenticated public traffic."""
    host = getattr(option, 'host_name', None)
    return (
        not getattr(option, 'unix', False)
        and host in (None, '', '0.0.0.0', '::')
        and not getattr(option, 'users', None)
    )
