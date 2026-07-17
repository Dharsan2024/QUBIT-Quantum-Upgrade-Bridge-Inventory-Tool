from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import AsyncGenerator

from pydantic import BaseModel


class SSEEvent(BaseModel):
    id: str
    event: str
    data: str


class EventBus:
    """
    In-memory ring buffer pub/sub for SSE.
    Maintains the last N events to support Last-Event-ID replay.
    """

    def __init__(self, capacity: int = 1024):
        self.capacity = capacity
        self.history: deque[SSEEvent] = deque(maxlen=capacity)
        # Using asyncio.Condition to notify subscribers of new events
        self.condition = asyncio.Condition()
        self._next_id = 1

    async def publish(self, event_type: str, data: dict[str, object] | str) -> None:
        """Publish a new event to the bus."""
        event_id = str(self._next_id)
        self._next_id += 1

        data_str = json.dumps(data) if isinstance(data, dict) else str(data)

        event = SSEEvent(id=event_id, event=event_type, data=data_str)

        async with self.condition:
            self.history.append(event)
            self.condition.notify_all()

    async def subscribe(self, last_event_id: str | None = None) -> AsyncGenerator[SSEEvent, None]:
        """Subscribe to events, yielding historical events if requested."""
        # Yield missed events from history first
        if last_event_id is not None:
            found = False
            async with self.condition:
                for idx, ev in enumerate(self.history):
                    if ev.id == last_event_id:
                        found = True
                        for missed_ev in list(self.history)[idx + 1 :]:
                            yield missed_ev
                        break
            if not found:
                # Client's last_event_id fell off the ring buffer.
                # In a real app, the client might need to refetch via REST.
                # Here we just yield the whole available history.
                for missed_ev in list(self.history):
                    yield missed_ev

        # Yield new events as they arrive
        last_yielded_id = str(self._next_id - 1) if self._next_id > 1 else None

        while True:
            async with self.condition:
                await self.condition.wait()
                # Yield all events newer than what we've seen
                for ev in self.history:
                    if last_yielded_id is None or int(ev.id) > int(last_yielded_id):
                        yield ev
                        last_yielded_id = ev.id
