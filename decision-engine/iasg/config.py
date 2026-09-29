from __future__ import annotations

import os
from dataclasses import dataclass, field, fields

from iasg.adaptive.config import AdaptiveConfig, load_adaptive_config

def _env_int(name: str,default : int) -> int:
    """read an int from the environment , falling back if unset or unparsable"""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1","true","yes","on")


def _env_tuple(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """A comma-separated list, e.g. IASG_ALLOWLIST=10.0.0.0/8,203.0.113.9"""
    raw = os.getenv(name)
    if raw is None:
        return default
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    redis_url: str = "redis://localhost:6379/0"

    evidence_stream : str = "iasg:events"
    consumer_group :str = "iasg-agent"
    consumer_name : str = "agent-1"
    batch_size: int = 500

    interval_seconds : int = 30
    # Written at the end of every cycle and given a TTL of a few intervals, so
    # a console can tell a stopped agent from a quiet network.
    heartbeat_key : str = "iasg:heartbeat"
    # Epoch-ms of the last "clear campaigns" reset, if any. Evidence stream
    # entries whose own id (Redis stream ids are "<ms>-<seq>", already time-
    # ordered) predates this are acked -- so a crash-recovery replay or a
    # consumer that was behind can't reprocess them -- but never correlated,
    # so they can't recreate a campaign the operator just cleared. Absent or
    # unset means no reset has ever happened, so nothing is filtered.
    reset_watermark_key : str = "iasg:reset_at"
    # policy writing , and the rails that keep it safe
    policy_prefix : str = "policy:"
    max_ips_per_cycle : int = 50
    dry_run : bool = False

    # Addresses and ranges this system will never write policy for, whatever
    # the evidence says. Your own monitoring, health checks and office range.
    allowlist : tuple[str, ...] = ()
    # Ranges known to be shared by many people -- an office NAT, a campus
    # gateway, carrier-grade NAT. Never blocked outright, only slowed.
    shared_ranges : tuple[str, ...] = ()
    # Distinct user agents from one address before it is *suspected* of being
    # shared. Inferred rather than declared, so it only ever softens the
    # ambiguous cases -- see policy/simulation.py.
    shared_address_agents : int = 5

    # Human overrides, and what the agent remembers from them.
    override_stream : str = "iasg_overrides"
    override_group : str = "iasg-overrides"
    feedback_prefix : str = "feedback:"
    # Consistent overrides in one direction before the agent shifts its own
    # recommendation. Two so a single unusual call cannot retrain it.
    feedback_min_samples : int = 2

    llm_provider : str = "null"
    ollama_url : str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    # How long one call may block. Narration runs inside the cycle, so a model
    # that hangs must give up well before the cycle is due to end.
    ollama_timeout_seconds : int = 15

    # Total wall-clock one cycle may spend on narration, across every campaign
    # and both agents. Once spent, the remaining campaigns fall back to their
    # templates rather than pushing the cycle past its interval: a late
    # decision is worse than an unnarrated one.
    narration_budget_seconds : int = 12

    postgres_url : str | None = None

    # The adaptive block is replaceable by a JSON value or JSON file through
    # IASG_ADAPTIVE_CONFIG.  A persisted dashboard value supersedes it at the
    # beginning of each cycle; this remains the validated boot/fallback value.
    adaptive: AdaptiveConfig = field(default_factory=AdaptiveConfig)

    # Separate groups let runtime windowing see clean traffic without changing
    # the evidence consumer's contract (which intentionally returns attacks).
    arrival_stream: str = "iasg:arrivals"
    health_stream: str = "iasg:telemetry:health"
    window_consumer_group: str = "iasg-windowing"
    window_consumer_name: str = "window-agent-1"
    window_completion_grace_seconds: int = 5

    @classmethod
    def from_env(cls) -> "Settings":
        """Every field reads IASG_<NAME>, parsed by the type of its default."""
        readers = {bool: _env_bool, int: _env_int, tuple: _env_tuple}
        values = {}
        for f in fields(cls):
            env = "IASG_" + f.name.upper()
            if f.name == "adaptive":
                values[f.name] = load_adaptive_config(os.getenv("IASG_ADAPTIVE_CONFIG"))
                continue
            default = getattr(cls, f.name)
            read = readers.get(type(default))
            values[f.name] = read(env, default) if read else os.getenv(env, default)
        return cls(**values)
