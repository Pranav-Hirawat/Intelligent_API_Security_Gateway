"""
Durable storage for what the agent has learned.

Redis is the transport and the hot path: the gateway reads policy:<ip> from it
on every request, and evidence arrives as a stream. Neither of those needs to
survive a restart -- a policy is meant to expire, and evidence that has been
correlated is done.

What does need to survive is the agent's memory: the campaigns it is tracking
and the corrections humans have made to it. Losing those turns an agent that
continues an investigation back into a script that starts over. That is what
this module keeps, and the reason policy keys are deliberately NOT here.

Entirely opt-in. With IASG_POSTGRES_URL unset -- or psycopg not installed, or
the server unreachable -- the control plane behaves exactly as it did before,
holding campaigns in Redis under a 24-hour TTL.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from iasg.adaptive.baseline import BaselineSummary, EndpointKey
from iasg.adaptive.config import AdaptiveConfig
from iasg.adaptive.lifecycle import Recommendation
from iasg.models import Campaign, PolicyDecision

# Campaigns older than this stop being offered to the correlator. It matches
# the TTL the Redis-backed path used, so switching stores does not change which
# campaigns a cycle can merge into -- only whether they survive a restart.
# Rows stay in the table afterwards; this bounds the working set, not history.
WORKING_SET = timedelta(hours=24)

SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id   BIGINT PRIMARY KEY,
    type          TEXT        NOT NULL,
    confidence    REAL        NOT NULL,
    severity      TEXT        NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'active',
    ips           TEXT[]      NOT NULL DEFAULT '{}',
    stages        TEXT[]      NOT NULL DEFAULT '{}',
    reason        TEXT        NOT NULL DEFAULT '',
    event_count   INTEGER     NOT NULL DEFAULT 0,
    quiet_cycles  INTEGER     NOT NULL DEFAULT 0,
    rotations     INTEGER     NOT NULL DEFAULT 0,
    persistence   INTEGER     NOT NULL DEFAULT 0,
    last_action   TEXT        NOT NULL DEFAULT '',
    outcome       TEXT        NOT NULL DEFAULT '',
    alerted       BOOLEAN     NOT NULL DEFAULT FALSE,
    explanation   TEXT        NOT NULL DEFAULT '',
    assessment    TEXT        NOT NULL DEFAULT '',
    signature     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    first_seen    TIMESTAMPTZ NOT NULL,
    last_seen     TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS campaigns_last_seen_idx ON campaigns (last_seen DESC);
CREATE INDEX IF NOT EXISTS campaigns_status_idx    ON campaigns (status);

-- One row per campaign type, not per correction: the agent only ever asks for
-- the net direction. See feedback/memory.py.
CREATE TABLE IF NOT EXISTS feedback (
    campaign_type TEXT PRIMARY KEY,
    up            INTEGER     NOT NULL DEFAULT 0,
    down          INTEGER     NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE SEQUENCE IF NOT EXISTS campaign_id_seq;

CREATE TABLE IF NOT EXISTS adaptive_settings (
    singleton_id  SMALLINT PRIMARY KEY CHECK (singleton_id = 1),
    version       INTEGER     NOT NULL,
    mode          TEXT        NOT NULL CHECK (mode IN ('monitor', 'manual', 'automatic')),
    config        JSONB       NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by    TEXT        NOT NULL DEFAULT 'bootstrap'
);

CREATE TABLE IF NOT EXISTS endpoint_baselines (
    method                TEXT        NOT NULL,
    route_template        TEXT        NOT NULL,
    sample_count          INTEGER     NOT NULL,
    statistic             DOUBLE PRECISION NOT NULL,
    mad                   DOUBLE PRECISION NOT NULL,
    derived_threshold     INTEGER     NOT NULL,
    observed_rate         INTEGER     NOT NULL,
    last_update           TIMESTAMPTZ,
    last_threshold_change TIMESTAMPTZ,
    version               INTEGER     NOT NULL,
    ready                 BOOLEAN     NOT NULL,
    samples               JSONB       NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (method, route_template)
);

CREATE TABLE IF NOT EXISTS policy_recommendations (
    policy_id       TEXT PRIMARY KEY,
    target_identity TEXT        NOT NULL,
    method          TEXT        NOT NULL DEFAULT '',
    route_template  TEXT        NOT NULL DEFAULT '',
    action          TEXT        NOT NULL,
    status          TEXT        NOT NULL,
    risk_score      DOUBLE PRECISION NOT NULL,
    confidence      DOUBLE PRECISION NOT NULL,
    mode            TEXT        NOT NULL,
    issued_by       TEXT        NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    payload         JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS policy_recommendations_status_idx
    ON policy_recommendations (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS policy_recommendations_scope_idx
    ON policy_recommendations (target_identity, method, route_template, updated_at DESC);

CREATE TABLE IF NOT EXISTS policy_audit (
    audit_id   BIGSERIAL PRIMARY KEY,
    policy_id  TEXT        NOT NULL,
    event      TEXT        NOT NULL,
    actor      TEXT        NOT NULL,
    details    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS policy_audit_created_idx ON policy_audit (created_at DESC);
"""

# Column order shared by the reader and both writers, so they cannot drift.
COLUMNS = (
    "campaign_id", "type", "confidence", "severity", "status", "ips", "stages",
    "reason", "event_count", "quiet_cycles", "rotations", "persistence",
    "last_action", "outcome", "alerted", "explanation", "assessment",
    "signature", "first_seen", "last_seen",
)


# The same column order for reading and writing baselines.
BASELINE_COLUMNS = (
    "method, route_template, sample_count, statistic, mad, derived_threshold,"
    " observed_rate, last_update, last_threshold_change, version, ready, samples"
)


class Database:
    """A live Postgres connection, plus the two things stored in it."""

    def __init__(self, dsn: str) -> None:
        import psycopg  # imported here so psycopg stays an optional extra

        # autocommit: every write here is a single statement, and a cycle that
        # crashes should leave behind what it had already decided.
        self._conn = psycopg.connect(dsn, autocommit=True, connect_timeout=5)
        with self._conn.cursor() as cur:
            cur.execute(SCHEMA)
            # Start the counter above whatever is already stored, so ids stay
            # unique across restarts and across a move from the Redis counter.
            cur.execute(
                "SELECT setval('campaign_id_seq',"
                " COALESCE((SELECT MAX(campaign_id) FROM campaigns), 0) + 1,"
                " false)"
            )

        self.campaigns = PostgresCampaigns(self._conn)
        self.feedback = PostgresFeedback(self._conn)
        self.adaptive = PostgresAdaptive(self._conn)

    def close(self) -> None:
        self._conn.close()


class PostgresCampaigns:
    """The three things CampaignRepository needs of a persistence layer."""

    def __init__(self, conn) -> None:
        self._conn = conn

    def all(self) -> list[Campaign]:
        """The working set: campaigns recent enough to still be merged into."""
        cutoff = datetime.now(timezone.utc) - WORKING_SET
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {', '.join(COLUMNS)} FROM campaigns"
                " WHERE last_seen >= %s ORDER BY last_seen DESC",
                (cutoff,),
            )
            return [_to_campaign(row) for row in cur.fetchall()]

    def save(self, campaign: Campaign, ttl_seconds: int = 0) -> None:
        """
        Upsert. ttl_seconds is accepted and ignored -- the point of this store
        is that campaigns do not expire, and the caller should not have to know
        which store it got.
        """
        placeholders = ", ".join(["%s"] * len(COLUMNS))
        updates = ", ".join(
            f"{c} = EXCLUDED.{c}" for c in COLUMNS if c != "campaign_id"
        )
        with self._conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO campaigns ({', '.join(COLUMNS)})"
                f" VALUES ({placeholders})"
                f" ON CONFLICT (campaign_id) DO UPDATE SET {updates},"
                " updated_at = now()",
                _to_row(campaign),
            )

    def next_id(self) -> str:
        with self._conn.cursor() as cur:
            cur.execute("SELECT nextval('campaign_id_seq')")
            return str(cur.fetchone()[0])


class PostgresFeedback:
    """What humans corrected, kept per campaign type."""

    def __init__(self, conn) -> None:
        self._conn = conn

    def tally(self, campaign_type: str) -> dict:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT up, down FROM feedback WHERE campaign_type = %s",
                (campaign_type,),
            )
            row = cur.fetchone()
        return {"up": row[0], "down": row[1]} if row else {}

    def bump(self, campaign_type: str, direction: str) -> None:
        """Add one correction in `direction` ("up" or "down")."""
        if direction not in ("up", "down"):
            return
        with self._conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO feedback (campaign_type, {direction})"
                " VALUES (%s, 1)"
                " ON CONFLICT (campaign_type) DO UPDATE"
                f" SET {direction} = feedback.{direction} + 1,"
                " updated_at = now()",
                (campaign_type,),
            )

    def all(self) -> dict[str, dict]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT campaign_type, up, down FROM feedback")
            return {
                row[0]: {"up": row[1], "down": row[2]} for row in cur.fetchall()
            }


class PostgresAdaptive:
    """Durable settings, endpoint learning, and complete policy lifecycle."""

    def __init__(self, conn) -> None:
        self._conn = conn

    def ensure_config(self, default: AdaptiveConfig) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO adaptive_settings (singleton_id, version, mode, config)"
                " VALUES (1, %s, %s, %s::jsonb) ON CONFLICT (singleton_id) DO NOTHING",
                (default.version, default.mode, json.dumps(default.to_dict())),
            )

    def load_config(self, default: AdaptiveConfig) -> AdaptiveConfig:
        with self._conn.cursor() as cur:
            cur.execute("SELECT config, version FROM adaptive_settings WHERE singleton_id = 1")
            row = cur.fetchone()
        if not row:
            self.ensure_config(default)
            return default
        value = row[0] if isinstance(row[0], dict) else json.loads(row[0])
        # Not strict: this row can predate the running code by many releases,
        # and a field a newer version retired must not wedge the agent every
        # cycle forever. IASG_ADAPTIVE_CONFIG (freshly authored each boot)
        # stays strict, so a typo there still fails loudly.
        try:
            config = AdaptiveConfig.from_mapping(value, default, strict=False)
        except ValueError as err:
            # Dropping unknown fields is not always enough: numbers a retired
            # field used to balance (weights that summed to 1 only together
            # with it) can survive the drop and still fail validate(). A
            # persisted row that predates the running code is not worth
            # trusting piecemeal at that point -- fall back to defaults rather
            # than repeat this cycle's failure forever.
            print(f"[adaptive] stored config rejected by this version ({err}); using defaults")
            config = default

        # The dashboard reads this durable document directly. Leaving retired
        # fields there means it faithfully sends them back on the next edit,
        # where strict validation rejects the same setting the agent ignored.
        # Persist the config actually in use so one cycle completes the
        # migration for every reader, rather than merely hiding it here.
        config = replace(config, version=int(row[1]))
        canonical = config.to_dict()
        if json.dumps(value, sort_keys=True) != json.dumps(canonical, sort_keys=True):
            with self._conn.cursor() as cur:
                cur.execute(
                    "UPDATE adaptive_settings SET mode=%s, config=%s::jsonb"
                    " WHERE singleton_id=1",
                    (config.mode, json.dumps(canonical)),
                )
        return config

    def get_baseline(self, key: EndpointKey) -> BaselineSummary | None:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {BASELINE_COLUMNS} FROM endpoint_baselines"
                " WHERE method = %s AND route_template = %s",
                (key.method, key.route_template),
            )
            row = cur.fetchone()
        return _to_baseline(row) if row else None

    def save_baseline(self, summary: BaselineSummary) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO endpoint_baselines ({BASELINE_COLUMNS})"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)"
                " ON CONFLICT (method, route_template) DO UPDATE SET"
                " sample_count=EXCLUDED.sample_count, statistic=EXCLUDED.statistic,"
                " mad=EXCLUDED.mad, derived_threshold=EXCLUDED.derived_threshold,"
                " observed_rate=EXCLUDED.observed_rate, last_update=EXCLUDED.last_update,"
                " last_threshold_change=EXCLUDED.last_threshold_change,"
                " version=EXCLUDED.version, ready=EXCLUDED.ready, samples=EXCLUDED.samples",
                (
                    summary.method, summary.route_template, summary.sample_count,
                    summary.statistic, summary.mad, summary.derived_threshold,
                    summary.observed_rate, summary.last_update,
                    summary.last_threshold_change, summary.version, summary.ready,
                    json.dumps(summary.samples),
                ),
            )

    def list_baselines(self) -> list[BaselineSummary]:
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {BASELINE_COLUMNS} FROM endpoint_baselines ORDER BY method, route_template"
            )
            return [_to_baseline(row) for row in cur.fetchall()]

    def save_recommendation(self, recommendation: Recommendation) -> None:
        decision = recommendation.decision
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO policy_recommendations"
                " (policy_id,target_identity,method,route_template,action,status,risk_score,"
                " confidence,mode,issued_by,expires_at,payload,created_at,updated_at)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)"
                " ON CONFLICT (policy_id) DO UPDATE SET"
                " target_identity=EXCLUDED.target_identity, method=EXCLUDED.method,"
                " route_template=EXCLUDED.route_template, action=EXCLUDED.action,"
                " status=EXCLUDED.status, risk_score=EXCLUDED.risk_score,"
                " confidence=EXCLUDED.confidence, mode=EXCLUDED.mode,"
                " issued_by=EXCLUDED.issued_by, expires_at=EXCLUDED.expires_at,"
                " payload=EXCLUDED.payload, updated_at=EXCLUDED.updated_at",
                (
                    decision.policy_id, decision.ip, decision.method,
                    decision.route_template, decision.action, recommendation.status,
                    decision.risk_score, decision.confidence, decision.mode,
                    decision.issued_by, decision.expires_at,
                    json.dumps(decision.to_dict()), recommendation.created_at,
                    recommendation.updated_at,
                ),
            )
            _audit(cur, decision.policy_id, recommendation.status, decision.issued_by)

    def approved_recommendations(self) -> list[Recommendation]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT payload,status,created_at,updated_at FROM policy_recommendations"
                " WHERE status='approved' ORDER BY updated_at"
            )
            return [_to_recommendation(row) for row in cur.fetchall()]

    def mark_status(self, policy_id: str, status: str, actor: str, details: dict | None = None) -> None:
        now = datetime.now(timezone.utc)
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE policy_recommendations SET status=%s, updated_at=%s WHERE policy_id=%s",
                (status, now, policy_id),
            )
            _audit(cur, policy_id, status, actor, details)

    def last_for_scope(self, decision: PolicyDecision) -> Recommendation | None:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT payload,status,created_at,updated_at FROM policy_recommendations"
                " WHERE target_identity=%s AND method=%s AND route_template=%s"
                " ORDER BY updated_at DESC LIMIT 1",
                (decision.ip, decision.method, decision.route_template),
            )
            row = cur.fetchone()
        return _to_recommendation(row) if row else None

    def expire_due(self, now: datetime) -> int:
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE policy_recommendations SET status='expired',updated_at=%s"
                " WHERE status='active' AND expires_at<=%s RETURNING policy_id",
                (now, now),
            )
            ids = [row[0] for row in cur.fetchall()]
            for policy_id in ids:
                _audit(cur, policy_id, "expired", "control-plane")
        return len(ids)


def open_database(settings) -> Database | None:
    """
    Connect, or return None and let the caller carry on with Redis.

    Durability is an upgrade, not a requirement. A missing driver or a database
    that is down must not stop the agent from defending anything.
    """
    if not settings.postgres_url:
        return None
    try:
        db = Database(settings.postgres_url)
        db.adaptive.ensure_config(settings.adaptive)
    except ImportError:
        print(
            "[postgres] psycopg not installed; campaigns stay in Redis. "
            'Install with: pip install -e ".[postgres]"'
        )
        return None
    except Exception as err:  # noqa: BLE001 - any connection failure degrades
        print(f"[postgres] unavailable ({err}); campaigns stay in Redis")
        return None

    print("[postgres] campaigns, adaptive settings, baselines, and policy audit are durable")
    return db


def _audit(cur, policy_id: str, event: str, actor: str, details: dict | None = None) -> None:
    cur.execute(
        "INSERT INTO policy_audit (policy_id,event,actor,details) VALUES (%s,%s,%s,%s::jsonb)",
        (policy_id, event, actor, json.dumps(details or {})),
    )


def _to_row(c: Campaign) -> tuple:
    return (
        int(c.campaign_id),
        c.type,
        float(c.confidence),
        c.severity,
        c.status,
        list(c.ips),
        list(c.stages),
        c.reason,
        int(c.event_count),
        int(c.quiet_cycles),
        int(c.rotations),
        int(c.persistence),
        c.last_action or "",
        c.outcome or "",
        bool(c.alerted),
        c.explanation or "",
        c.assessment or "",
        json.dumps(c.signature or {}),
        c.first_seen,
        c.last_seen,
    )


def _to_campaign(row: tuple) -> Campaign:
    signature = row[17]
    # psycopg returns jsonb already decoded; tolerate a string either way.
    if isinstance(signature, str):
        try:
            signature = json.loads(signature)
        except ValueError:
            signature = {}

    return Campaign(
        campaign_id=str(row[0]),
        type=row[1],
        confidence=float(row[2]),
        severity=row[3],
        status=row[4],
        ips=list(row[5] or []),
        stages=list(row[6] or []),
        reason=row[7],
        event_count=row[8],
        quiet_cycles=row[9],
        rotations=row[10],
        persistence=row[11],
        last_action=row[12],
        outcome=row[13],
        alerted=row[14],
        explanation=row[15],
        assessment=row[16],
        signature=signature or {},
        first_seen=_utc(row[18]),
        last_seen=_utc(row[19]),
    )


def _utc(value: datetime | None) -> datetime | None:
    """
    Postgres hands TIMESTAMPTZ back in the session's timezone, which is
    whatever the server was configured with. Everything else in the project
    works in UTC and formats times for display without converting, so a
    campaign loaded from here would otherwise print its start in local time
    and its end in UTC -- "between 11:55 and 06:27" for ninety seconds of
    attack. Comparisons were always correct; only the reading was wrong.
    """
    if value is None:
        return None
    return value.astimezone(timezone.utc)


def _to_baseline(row: tuple) -> BaselineSummary:
    samples = row[11]
    if isinstance(samples, str):
        samples = json.loads(samples)
    return BaselineSummary(
        method=row[0], route_template=row[1], sample_count=row[2],
        statistic=float(row[3]), mad=float(row[4]), derived_threshold=row[5],
        observed_rate=row[6], last_update=_utc(row[7]),
        last_threshold_change=_utc(row[8]), version=row[9], ready=row[10],
        samples=[float(value) for value in (samples or [])],
    )


def _to_recommendation(row: tuple) -> Recommendation:
    payload = row[0] if isinstance(row[0], dict) else json.loads(row[0])
    return Recommendation(
        decision=PolicyDecision.from_dict(payload), status=row[1],
        created_at=_utc(row[2]), updated_at=_utc(row[3]),
    )
