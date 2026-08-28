"""Small task registry used by proxy runtime objects."""

import asyncio
from collections.abc import Awaitable
from typing import Any


class TaskRegistry(set):
    """Track tasks created by one runtime owner.

    The set-compatible surface keeps inspection and existing cleanup code
    simple while adding a single place for task creation and shutdown.
    """

    def create_task(
        self,
        awaitable: Awaitable[Any],
        *,
        name: str | None = None,
    ) -> asyncio.Task[Any]:
        """Create, track, and automatically forget one asyncio task."""
        task = asyncio.create_task(awaitable, name=name)
        self.add(task)
        task.add_done_callback(self.discard)
        return task

    def cancel_all(self) -> None:
        """Request cancellation for every task currently being tracked."""
        for task in tuple(self):
            task.cancel()

    async def wait_closed(self) -> None:
        """Wait for all currently tracked tasks and forget them."""
        tasks = tuple(self)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.clear()
