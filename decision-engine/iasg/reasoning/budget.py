"""
A spending cap on narration.

Explanation and assessment run inside the cycle, once per campaign each, so
their cost scales with how bad the hour is. A busy cycle with six campaigns is
twelve model calls, and at a few seconds apiece that is longer than the
interval the agent is supposed to run on -- so the cycle that mattered most is
the one that would arrive late.

This wraps a provider and stops calling it once a cycle has spent its budget.
Callers see the same "" that a missing or broken provider returns, and fall
back to their templates. Narration degrades; the cycle keeps its schedule.
"""

from __future__ import annotations

import time

from iasg.reasoning.provider import LLMProvider


class BudgetedProvider:
    def __init__(self, inner: LLMProvider, budget_seconds: float) -> None:
        self._inner = inner
        self._budget = max(0.0, float(budget_seconds))
        self._spent = 0.0
        # Counted so the cycle report can say narration was cut short rather
        # than leaving an operator to wonder why some campaigns read
        # differently from others.
        self.skipped = 0

    @property
    def name(self) -> str:
        return getattr(self._inner, "name", "unknown")

    def begin_cycle(self) -> None:
        """Restore the full budget. Called once per cycle, before any call."""
        self._spent = 0.0
        self.skipped = 0

    @property
    def exhausted(self) -> bool:
        return self._spent >= self._budget

    def generate(self, system: str, prompt: str) -> str:
        if self.exhausted:
            self.skipped += 1
            return ""

        started = time.monotonic()
        try:
            return self._inner.generate(system, prompt)
        finally:
            # Charged in a finally block so a call that raised still costs what
            # it burned. Otherwise a provider that reliably times out would be
            # free, and would be retried for every campaign in the cycle.
            self._spent += time.monotonic() - started
