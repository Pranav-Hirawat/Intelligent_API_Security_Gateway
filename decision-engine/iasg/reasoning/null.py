"""No LLM. Callers fall back to their templates."""

from __future__ import annotations


class NullProvider:
    name = "null"

    def generate(self, system: str, prompt: str) -> str:
        return ""
