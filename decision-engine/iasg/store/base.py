"""
The Store interface -- everything this projects needs redis , in one list.

Two classes will implement it:
    MemoryStore -- a fake , for tests . No Redis needed
    RedisStore  -- the real one.

Everything else in the project accepts a "Store" without caring which it got.
That is what lets the whole pipeline be tested without a database running
"""

from __future__ import annotations

from typing import Protocol

class Store(Protocol):
    def ensure_group(self, stream: str, group: str) -> None:
        """
        Create the consumer group if it doesn't exist yet.

        A "consumer group" is Redis remembering how far we've read. Without it,
        restarting the agent would re-process every attack from the beginning
        of time. Safe to call repeatedly -- doing nothing when it already
        exists is the expected case.
        """
        ...

    def read_group(
            self,
            stream :  str,
            group: str,
            consumer : str,
            count : int,
            block_ms : int = 0,
    ) -> list[tuple[str,dict[str,str]]]:
        pass

    def read_pending(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int,
    ) -> list[tuple[str, dict[str, str]]]:
        """Re-read entries handed out but never acked. Crash recovery."""
        ...

    def ack(self, stream: str, group: str, *ids: str) -> int:
        pass
    
    def append(self , stream: str, fields: dict[str,str]) -> str:
        pass

    def trim(self, stream: str, maxlen: int) -> int:
        """Remove old entries without deleting the stream's consumer groups."""
        ...

    def get(self, key: str) -> str | None:
        pass

    def set(self,key:str,value:str,ttl_seconds:int | None = None) -> None:
        pass

    def keys(self, pattern: str) -> list[str]:
        pass

    def close(self) -> None:
        pass
