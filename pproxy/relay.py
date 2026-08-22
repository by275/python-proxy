"""Bidirectional stream relay orchestration."""

import asyncio


async def relay_with_taskgroup(inbound, outbound):
    """Run both relay directions under one cancellation scope."""
    async with asyncio.TaskGroup() as task_group:
        task_group.create_task(inbound)
        task_group.create_task(outbound)
