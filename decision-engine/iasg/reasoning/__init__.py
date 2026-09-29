"""LLM providers. Text generation only -- never decisions."""

from __future__ import annotations

from iasg.config import Settings
from iasg.reasoning.budget import BudgetedProvider
from iasg.reasoning.null import NullProvider
from iasg.reasoning.ollama import OllamaProvider
from iasg.reasoning.provider import LLMProvider

__all__ = [
    "BudgetedProvider",
    "LLMProvider",
    "NullProvider",
    "OllamaProvider",
    "open_provider",
]


def open_provider(settings: Settings) -> LLMProvider:
    """
    The provider the agents narrate through.

    A real provider is wrapped in a spending cap. NullProvider is not: it
    returns "" without doing any work, so there is nothing to budget, and
    leaving it bare keeps the no-LLM path exactly as cheap as it was.
    """
    if settings.llm_provider == "ollama":
        return BudgetedProvider(
            OllamaProvider(
                settings.ollama_url,
                settings.ollama_model,
                settings.ollama_timeout_seconds,
            ),
            settings.narration_budget_seconds,
        )
    return NullProvider()
