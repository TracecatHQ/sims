import asyncio
from typing import Callable


class DelayedDetonator:

    def __init__(self, delay_seconds: int, detonate: Callable, **kwargs):
        self.delay_seconds = delay_seconds
        self._detonate = detonate
        self._detonate_kwargs = kwargs

    async def run(self):
        """Detonate attack after `delay_seconds`.
        """
        await asyncio.sleep(self.delay_seconds)
        await asyncio.to_thread(self._detonate(**self._detonate_kwargs))
