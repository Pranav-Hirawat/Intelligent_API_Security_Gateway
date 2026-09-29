"""What a text generator has to offer this project."""

from __future__ import annotations

from typing import Protocol


class LLMProvider(Protocol):
    def generate(self, system: str, prompt: str) -> str:
        """
        Return generated text, or "" when unavailable.

        Returning "" rather than raising is deliberate: callers fall back to a
        template, so a missing or broken LLM degrades the output instead of
        failing the cycle.
        """
        ...
