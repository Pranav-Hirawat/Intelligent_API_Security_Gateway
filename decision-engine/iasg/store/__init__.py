"""Store implementations."""

from __future__ import annotations

from iasg.config import Settings
from iasg.store.base import Store
from iasg.store.memory import MemoryStore
from iasg.store.redis_store import RedisStore

__all__ = ["Store", "MemoryStore", "RedisStore", "open_store"]


def open_store(settings: Settings) -> Store:
    """Connect to Redis, or fall back to memory if it isn't reachable."""
    try:
        return RedisStore(settings.redis_url)
    except Exception as err:
        print(f"[store] redis unavailable ({err}); using in-memory store")
        return MemoryStore()
