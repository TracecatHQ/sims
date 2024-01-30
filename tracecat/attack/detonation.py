import asyncio
from typing import Callable


async def delayed_detonate(delay_seconds: int, detonate: Callable):
    """Detonate attack after N seconds.
    """
    await asyncio.sleep(delay_seconds)
    await asyncio.to_thread(detonate())
