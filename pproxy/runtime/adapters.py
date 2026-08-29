"""Formal lifecycle contract for optional transport adapters."""

from dataclasses import dataclass
from typing import Any, ClassVar, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    """Describe the runtime surface provided by one optional adapter."""

    name: str
    dependency: str
    supports_streams: bool
    supports_datagrams: bool
    multiplexed: bool
    owns_shared_session: bool


@runtime_checkable
class OptionalAdapter(Protocol):
    """Structural contract shared by optional transport implementations.

    Adapters must expose their capabilities and return the project's reader/
    writer pair from ``wait_open_connection()``. ``close()`` must be
    idempotent and request shutdown without blocking. ``wait_closed()`` must
    wait for all adapter-owned tasks, streams, and shared sessions after close,
    while ``aclose()`` combines both operations.

    Missing optional dependencies must raise ``ConfigurationError`` before a
    resource is published. Connection failures should preserve their original
    connection/protocol exception type. Cancellation must propagate
    ``asyncio.CancelledError`` after closing resources created by the canceled
    operation.
    """

    adapter_capabilities: ClassVar[AdapterCapabilities]

    def close(self) -> None:
        """Request idempotent shutdown of adapter-owned resources."""

    async def wait_closed(self) -> None:
        """Wait for resources released by a prior close request."""

    async def aclose(self) -> None:
        """Request shutdown and wait for completion."""

    async def wait_open_connection(
        self,
        host: str | None,
        port: int | None,
        local_addr: Any,
        family: int,
    ) -> tuple[Any, Any]:
        """Open one adapter stream using the project's stream contract."""


def require_optional_adapter(adapter: object) -> OptionalAdapter:
    """Validate and return an object implementing the optional contract."""
    if (
        not isinstance(adapter, OptionalAdapter)
        or not isinstance(getattr(adapter, 'adapter_capabilities', None), AdapterCapabilities)
    ):
        raise TypeError(f'{type(adapter).__name__} does not implement OptionalAdapter')
    return adapter
