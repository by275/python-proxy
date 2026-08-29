"""Runtime ownership helpers for long-lived proxy tasks."""

from .adapters import AdapterCapabilities, OptionalAdapter, require_optional_adapter
from .tasks import TaskRegistry
from .policy import (
    ADMIN_BODY_LIMIT,
    DEFAULT_LISTENER_URI,
    H2_STREAM_LIMIT,
    HTTP_HEADER_LIMIT,
    UDP_LIMIT,
    UDP_TASK_LIMIT,
    WEBSOCKET_FRAME_LIMIT,
    WEBSOCKET_MESSAGE_LIMIT,
    is_unauthenticated_wildcard,
)

__all__ = [
    'AdapterCapabilities',
    'OptionalAdapter',
    'require_optional_adapter',
    'TaskRegistry',
    'ADMIN_BODY_LIMIT',
    'DEFAULT_LISTENER_URI',
    'H2_STREAM_LIMIT',
    'HTTP_HEADER_LIMIT',
    'UDP_LIMIT',
    'UDP_TASK_LIMIT',
    'WEBSOCKET_FRAME_LIMIT',
    'WEBSOCKET_MESSAGE_LIMIT',
    'is_unauthenticated_wildcard',
]
