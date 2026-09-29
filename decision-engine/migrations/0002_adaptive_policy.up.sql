BEGIN;

CREATE TABLE IF NOT EXISTS adaptive_settings (
    singleton_id SMALLINT PRIMARY KEY CHECK (singleton_id = 1),
    version INTEGER NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('monitor', 'manual', 'automatic')),
    config JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT NOT NULL DEFAULT 'bootstrap'
);

CREATE TABLE IF NOT EXISTS endpoint_baselines (
    method TEXT NOT NULL,
    route_template TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    statistic DOUBLE PRECISION NOT NULL,
    mad DOUBLE PRECISION NOT NULL,
    derived_threshold INTEGER NOT NULL,
    observed_rate INTEGER NOT NULL,
    last_update TIMESTAMPTZ,
    last_threshold_change TIMESTAMPTZ,
    version INTEGER NOT NULL,
    ready BOOLEAN NOT NULL,
    samples JSONB NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (method, route_template)
);

CREATE TABLE IF NOT EXISTS policy_recommendations (
    policy_id TEXT PRIMARY KEY,
    target_identity TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT '',
    route_template TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    risk_score DOUBLE PRECISION NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    mode TEXT NOT NULL,
    issued_by TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS policy_recommendations_status_idx
    ON policy_recommendations (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS policy_recommendations_scope_idx
    ON policy_recommendations (target_identity, method, route_template, updated_at DESC);

CREATE TABLE IF NOT EXISTS policy_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    policy_id TEXT NOT NULL,
    event TEXT NOT NULL,
    actor TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS policy_audit_created_idx ON policy_audit (created_at DESC);

COMMIT;
