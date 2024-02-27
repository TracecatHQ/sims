import asyncio
from typing import Callable


class DelayedDetonator:
    def __init__(self, delay: int, detonate: Callable, **kwargs):
        self.delay = delay
        self._detonate = detonate
        self._detonate_kwargs = kwargs

    async def run(self):
        """Detonate attack after `delay`."""
        await asyncio.sleep(self.delay)
        await asyncio.to_thread(self._detonate, **self._detonate_kwargs)
