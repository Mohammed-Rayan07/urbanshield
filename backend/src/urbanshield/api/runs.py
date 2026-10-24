"""Run registry: per-run event history that SSE clients replay and then follow. Owner: C.

The orchestrator runs in a worker thread and pushes events here; any number of SSE
subscribers (asyncio) replay everything so far, then wait for more. A browser refresh mid-run
therefore loses nothing. Waking a subscriber crosses threads with ``call_soon_threadsafe``.
"""

from __future__ import annotations

import asyncio
import threading
from collections import OrderedDict
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from urbanshield.agents.orchestrator import ApprovalGate
from urbanshield.agents.tools import RunContext
from urbanshield.schemas import AgentEvent

KEEPALIVE_S = 15.0


@dataclass
class RunState:
    run_id: str
    city_id: str
    gate: ApprovalGate = field(default_factory=ApprovalGate)
    ctx: RunContext | None = None
    events: list[AgentEvent] = field(default_factory=list)
    done: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _waiters: set[tuple[asyncio.AbstractEventLoop, asyncio.Event]] = field(default_factory=set)

    def push(self, event: AgentEvent) -> None:
        with self._lock:
            self.events.append(event)
        self._wake()

    def finish(self) -> None:
        with self._lock:
            self.done = True
        self._wake()

    def _wake(self) -> None:
        with self._lock:
            waiters = list(self._waiters)
        for loop, flag in waiters:
            loop.call_soon_threadsafe(flag.set)

    def _since(self, index: int) -> tuple[list[AgentEvent], bool]:
        with self._lock:
            return self.events[index:], self.done

    async def follow(self) -> AsyncIterator[AgentEvent | None]:
        """Every event from the start, then new ones as they arrive; ``None`` = keep-alive."""
        flag = asyncio.Event()
        waiter = (asyncio.get_running_loop(), flag)
        with self._lock:
            self._waiters.add(waiter)
        try:
            index = 0
            while True:
                flag.clear()
                batch, done = self._since(index)
                for event in batch:
                    yield event
                index += len(batch)
                if done and not batch:
                    return
                if batch:
                    continue
                try:
                    await asyncio.wait_for(flag.wait(), KEEPALIVE_S)
                except TimeoutError:
                    yield None
        finally:
            with self._lock:
                self._waiters.discard(waiter)


class RunRegistry:
    """Bounded: at most ``max_active`` running at once, the newest ``keep`` runs remembered."""

    def __init__(self, max_active: int = 2, keep: int = 50) -> None:
        self.max_active = max_active
        self.keep = keep
        self._runs: OrderedDict[str, RunState] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, run_id: str) -> RunState | None:
        with self._lock:
            return self._runs.get(run_id)

    def active(self) -> int:
        with self._lock:
            return sum(not r.done for r in self._runs.values())

    def add(self, state: RunState) -> bool:
        """Register a new run; False if too many are already running."""
        with self._lock:
            if sum(not r.done for r in self._runs.values()) >= self.max_active:
                return False
            self._runs[state.run_id] = state
            while len(self._runs) > self.keep:
                oldest = next((k for k, r in self._runs.items() if r.done), None)
                if oldest is None:
                    break
                del self._runs[oldest]
            return True
