"""Settings come from IASG_* environment variables, typed by their default."""

from __future__ import annotations

import os

from iasg.config import Settings


def test_unset_variables_keep_the_defaults(monkeypatch):
    for name in list(os.environ):
        if name.startswith("IASG_"):
            monkeypatch.delenv(name)
    assert Settings.from_env() == Settings()


def test_each_variable_is_read_as_its_settings_type(monkeypatch):
    monkeypatch.setenv("IASG_INTERVAL_SECONDS", "45")
    monkeypatch.setenv("IASG_DRY_RUN", "yes")
    monkeypatch.setenv("IASG_ALLOWLIST", "10.0.0.0/8, 203.0.113.9,,")
    monkeypatch.setenv("IASG_REDIS_URL", "redis://cache:6379/2")

    s = Settings.from_env()
    assert s.interval_seconds == 45
    assert s.dry_run is True
    assert s.allowlist == ("10.0.0.0/8", "203.0.113.9")
    assert s.redis_url == "redis://cache:6379/2"


def test_an_unreadable_number_falls_back_rather_than_stopping_the_agent(monkeypatch):
    monkeypatch.setenv("IASG_MAX_IPS_PER_CYCLE", "fifty")
    assert Settings.from_env().max_ips_per_cycle == Settings().max_ips_per_cycle


def test_only_clear_yes_words_turn_a_switch_on(monkeypatch):
    for value, expected in (("1", True), ("TRUE", True), (" on ", True), ("0", False), ("nope", False)):
        monkeypatch.setenv("IASG_DRY_RUN", value)
        assert Settings.from_env().dry_run is expected, value
