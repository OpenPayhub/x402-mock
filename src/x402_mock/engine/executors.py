"""
Event chain execution engine.

Provides workflow orchestration on top of EventBus, processing events
recursively until termination conditions are met.
"""

import asyncio
from typing import AsyncGenerator, Optional

from .events import BaseEvent, BreakEvent, EventBus, Dependencies


class EventChain:
    """Executes event-driven workflows by chaining event handler results.
    
    Supports early return mechanism: when an event matching early_return_on is encountered,
    execute() returns that event immediately while remaining processing continues in background.
    """
    
    def __init__(
        self, 
        event_bus: EventBus, 
        deps: Dependencies, 
    ) -> None:
        """
        Initialize event chain executor.
        
        Args:
            event_bus: The event bus to dispatch events through.
            deps: Dependencies container to pass to handlers.
        """
        self.event_bus = event_bus
        self.deps = deps
    
    async def execute(self, initial_event: BaseEvent) -> AsyncGenerator[BaseEvent, None]:
        """
        Execute event chain starting from initial event.
        
        Returns:
            Yields events encountered during chain execution.
            
        Note:
            When early return is triggered, subsequent events continue processing 
            asynchronously in background without blocking the return.
        """
        events_queue = asyncio.Queue()
        
        async def producer():
            async for event in self._process_event(initial_event):
                await events_queue.put(event)
            await events_queue.put(None)  # Sentinel to indicate completion
        
        asyncio.create_task(producer())
        
        while True:
            event = await events_queue.get()
            if event is None:  # Chain complete
                break
            yield event

    async def _process_event(self, event: BaseEvent) -> AsyncGenerator[BaseEvent, None]:
        """
        Process single event and recursively handle results.
        
        Args:
            event: The event to process.
        
        Yields:
            Events from the chain.
        """
        if isinstance(event, BreakEvent):
            return
        
        async for result in self.event_bus.dispatch(event, self.deps):
            if result is None:
                continue
            if isinstance(result, BaseEvent):
                yield result
                async for e in self._process_event(result):
                    yield e
            else:
                raise TypeError(f"Handler returned unsupported type: {type(result).__name__}")
