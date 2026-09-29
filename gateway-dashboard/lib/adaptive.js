import { getPool } from "./postgres";
import { isIP } from "node:net";
import { normalizeStoredAdaptive } from "./adaptive-config.mjs";

export const MODES = ["monitor", "manual", "automatic"];
export const ACTIONS = ["monitor", "throttle", "temp_block"];

export function validateAdaptive(config) {
  if (!config || typeof config !== "object") return "expected an adaptive configuration object";
  const unknownTop = unknownKeys(config, ["version", "mode", "baseline", "risk", "guardrails"]);
  if (unknownTop) return `unknown adaptive setting: ${unknownTop}`;
  if (!integerBetween(config.version, 1, Number.MAX_SAFE_INTEGER)) return "configuration version must be a positive integer";
  if (!MODES.includes(config.mode)) return `mode must be one of ${MODES.join(", ")}`;
  const b = config.baseline || {};
  const r = config.risk || {};
  const g = config.guardrails || {};
  const unknownBaseline = unknownKeys(b, ["method", "window_seconds", "rolling_windows", "warmup_windows", "mad_multiplier", "minimum_mad", "minimum_threshold_rpm", "maximum_threshold_rpm", "hysteresis_ratio", "cooldown_seconds"]);
  if (unknownBaseline) return `unknown baseline setting: ${unknownBaseline}`;
  const unknownRisk = unknownKeys(r, ["deterministic_weight", "behavioural_weight", "campaign_weight", "detector_points", "repeated_evidence_increment", "severity_multipliers", "throttle_score", "temporary_block_score", "confidence_deterministic_weight", "confidence_campaign_weight"]);
  if (unknownRisk) return `unknown risk setting: ${unknownRisk}`;
  const unknownGuard = unknownKeys(g, ["maximum_automatic_action", "minimum_confidence_throttle", "minimum_confidence_temporary_block", "maximum_policy_duration_seconds", "monitor_duration_seconds", "throttle_duration_seconds", "temporary_block_duration_seconds", "minimum_throttle_rpm", "maximum_throttle_rpm", "default_throttle_rpm", "throttle_baseline_fraction", "behavioural_throttle_enabled", "behavioural_throttle_minimum_deviation", "policy_cooldown_seconds", "minimum_deterministic_evidence_throttle", "minimum_deterministic_evidence_temporary_block", "analyst_escalation_confidence", "analyst_escalation_min_clients", "analyst_escalation_min_stages", "allowlist", "blocklist"]);
  if (unknownGuard) return `unknown guardrail setting: ${unknownGuard}`;
  if (b.method !== "median_mad") return "baseline.method must be median_mad";
  if (b.window_seconds !== 60) return "baseline.window_seconds must remain 60";
  if (!integerBetween(b.rolling_windows, 3, 1440)) return "baseline.rolling_windows must be 3..1440";
  if (!integerBetween(b.warmup_windows, 1, b.rolling_windows)) return "baseline.warmup_windows must be 1..rolling_windows";
  if (!numberBetween(b.mad_multiplier, 0.1, 20)) return "baseline.mad_multiplier must be 0.1..20";
  if (!numberBetween(b.minimum_mad, 0, 1000)) return "baseline.minimum_mad must be 0..1000";
  if (!integerBetween(b.minimum_threshold_rpm, 1, 100000)) return "minimum endpoint threshold must be 1..100000";
  if (!integerBetween(b.maximum_threshold_rpm, b.minimum_threshold_rpm, 100000)) return "maximum endpoint threshold must be above its minimum";
  if (!numberBetween(b.hysteresis_ratio, 0, 0.5)) return "baseline.hysteresis_ratio must be 0..0.5";
  if (!integerBetween(b.cooldown_seconds, 0, 86400)) return "baseline.cooldown_seconds must be 0..86400";

  const weights = [r.deterministic_weight, r.behavioural_weight, r.campaign_weight];
  if (weights.some((value) => !numberBetween(value, 0, 1)) || Math.abs(weights.reduce((a, b2) => a + b2, 0) - 1) > 0.001) {
    return "risk weights must each be 0..1 and total 1";
  }
  if (!numberBetween(r.throttle_score, 0, 100) || !numberBetween(r.temporary_block_score, 0, 100) || r.temporary_block_score <= r.throttle_score) {
    return "risk action thresholds must be ordered within 0..100";
  }
  if (!r.detector_points || Object.values(r.detector_points).some((value) => !numberBetween(value, 0, 100))) {
    return "detector points must be within 0..100";
  }
  if (!r.severity_multipliers || Object.values(r.severity_multipliers).some((value) => !numberBetween(value, 0, 1))) {
    return "severity multipliers must be within 0..1";
  }
  if (!numberBetween(r.repeated_evidence_increment, 0, 100)) return "repeated evidence increment must be 0..100";
  if (Math.abs(Number(r.confidence_deterministic_weight) + Number(r.confidence_campaign_weight) - 1) > 0.01 ||
      !numberBetween(r.confidence_deterministic_weight, 0, 1) || !numberBetween(r.confidence_campaign_weight, 0, 1)) {
    return "policy-confidence weights must each be 0..1 and total 1";
  }
  if (!ACTIONS.includes(g.maximum_automatic_action)) return "invalid maximum automatic action";
  if (!numberBetween(g.minimum_confidence_throttle, 0, 1) || !numberBetween(g.minimum_confidence_temporary_block, 0, 1)) {
    return "confidence guardrails must be within 0..1";
  }
  if (g.minimum_confidence_temporary_block < g.minimum_confidence_throttle) return "temporary-block confidence cannot be below throttle confidence";
  if (!integerBetween(g.maximum_policy_duration_seconds, 30, 86400)) return "maximum policy duration must be 30..86400 seconds";
  for (const name of ["monitor_duration_seconds", "throttle_duration_seconds", "temporary_block_duration_seconds"]) {
    if (!integerBetween(g[name], 1, g.maximum_policy_duration_seconds)) return `${name} exceeds the maximum policy duration`;
  }
  if (!integerBetween(g.minimum_throttle_rpm, 1, 100000) ||
      !integerBetween(g.default_throttle_rpm, g.minimum_throttle_rpm, 100000) ||
      !integerBetween(g.maximum_throttle_rpm, g.default_throttle_rpm, 100000)) {
    return "throttle rates must be ordered within 1..100000";
  }
  if (!numberBetween(g.throttle_baseline_fraction, 0.01, 1)) return "throttle baseline fraction must be 0.01..1";
  if (g.behavioural_throttle_enabled !== undefined && typeof g.behavioural_throttle_enabled !== "boolean") {
    return "behavioural throttle enablement must be true or false";
  }
  if (g.behavioural_throttle_minimum_deviation !== undefined &&
      !numberBetween(g.behavioural_throttle_minimum_deviation, 0.1, 100)) {
    return "behavioural throttle deviation must be 0.1..100";
  }
  if (!integerBetween(g.policy_cooldown_seconds, 0, 86400)) return "policy cooldown must be 0..86400 seconds";
  if (!numberBetween(g.analyst_escalation_confidence, 0, 1)) return "analyst escalation confidence must be 0..1";
  if (!integerBetween(g.analyst_escalation_min_clients, 1, 100000) || !integerBetween(g.analyst_escalation_min_stages, 2, 20)) return "analyst escalation size/stage minimums are invalid";
  if (!integerBetween(g.minimum_deterministic_evidence_throttle, 1, 1000) ||
      !integerBetween(g.minimum_deterministic_evidence_temporary_block, g.minimum_deterministic_evidence_throttle, 1000)) {
    return "deterministic evidence minimums are invalid";
  }
  if (!Array.isArray(g.allowlist) || !Array.isArray(g.blocklist)) return "allowlist and blocklist must be arrays";
  for (const [name, entries] of [["allowlist", g.allowlist], ["blocklist", g.blocklist]]) {
    if (entries.some((entry) => !isAddressOrCidr(entry))) return `${name} contains an invalid address or CIDR`;
  }
  return null;
}

export async function readAdaptive() {
  const pool = getPool();
  if (!pool) return { available: false, error: "IASG_POSTGRES_URL is unset" };
  try {
    const [settings, baselines, recommendations, audit] = await Promise.all([
      pool.query("SELECT config, file_config, source, updated_at, updated_by FROM adaptive_settings WHERE singleton_id=1"),
      pool.query(`SELECT method, route_template, sample_count, statistic, mad,
                         derived_threshold, observed_rate, last_update, version, ready
                    FROM endpoint_baselines ORDER BY method, route_template`),
      pool.query(`SELECT policy_id, target_identity, method, route_template, action, status,
                         risk_score, confidence, mode, issued_by, expires_at, payload,
                         created_at, updated_at
                    FROM policy_recommendations ORDER BY updated_at DESC LIMIT 200`),
      pool.query(`SELECT audit_id, policy_id, event, actor, details, created_at
                    FROM policy_audit ORDER BY created_at DESC LIMIT 300`),
    ]);
    return {
      available: true,
      config: normalizeStoredAdaptive(settings.rows[0]?.config || null),
      fileConfig: normalizeStoredAdaptive(settings.rows[0]?.file_config || null),
      source: settings.rows[0]?.source === "console" ? "console" : "file",
      settingsUpdatedAt: settings.rows[0]?.updated_at || null,
      settingsUpdatedBy: settings.rows[0]?.updated_by || "",
      baselines: baselines.rows.map((row) => ({
        method: row.method,
        routeTemplate: row.route_template,
        sampleCount: row.sample_count,
        statistic: Number(row.statistic),
        mad: Number(row.mad),
        threshold: row.derived_threshold,
        observedRate: row.observed_rate,
        lastUpdate: row.last_update,
        version: row.version,
        ready: row.ready,
      })),
      recommendations: recommendations.rows.map((row) => ({
        policyId: row.policy_id,
        targetIdentity: row.target_identity,
        method: row.method,
        routeTemplate: row.route_template,
        action: row.action,
        status: row.status,
        riskScore: Number(row.risk_score),
        confidence: Number(row.confidence),
        mode: row.mode,
        issuedBy: row.issued_by,
        expiresAt: row.expires_at,
        explanation: row.payload?.explanation || {},
        reason: row.payload?.reason || "",
        requestsPerMinute: Number(row.payload?.requests_per_minute || 0),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
      audit: audit.rows.map((row) => ({
        auditId: String(row.audit_id), policyId: row.policy_id, event: row.event,
        actor: row.actor, details: row.details || {}, createdAt: row.created_at,
      })),
    };
  } catch (err) {
    return { available: false, error: err.message, baselines: [], recommendations: [], audit: [] };
  }
}

export function validateRecommendationEdit(payload, config) {
  const action = payload.action;
  const guard = config.guardrails;
  if (!ACTIONS.includes(action)) return "invalid action";
  if (!integerBetween(payload.expires_in, 1, guard.maximum_policy_duration_seconds)) {
    return "duration exceeds the configured guardrail";
  }
  if (action === "throttle" && !integerBetween(
    payload.requests_per_minute, guard.minimum_throttle_rpm, guard.maximum_throttle_rpm,
  )) return "throttle rate is outside configured endpoint bounds";
  const confidence = Number(payload.confidence || 0);
  const evidence = Number(payload.explanation?.deterministic_evidence_count || 0);
  if (action === "throttle" && confidence < guard.minimum_confidence_throttle) {
    return "recommendation confidence is below the throttle guardrail";
  }
  if (action === "throttle" && evidence < guard.minimum_deterministic_evidence_throttle) {
    return "recommendation evidence is below the throttle guardrail";
  }
  if (action === "temp_block" && confidence < guard.minimum_confidence_temporary_block) {
    return "recommendation confidence is below the temporary-block guardrail";
  }
  if (action === "temp_block" && evidence < guard.minimum_deterministic_evidence_temporary_block) {
    return "recommendation evidence is below the temporary-block guardrail";
  }
  return null;
}

function integerBetween(value, low, high) {
  return Number.isInteger(value) && value >= low && value <= high;
}

function numberBetween(value, low, high) {
  return typeof value === "number" && Number.isFinite(value) && value >= low && value <= high;
}

function isAddressOrCidr(value) {
  if (typeof value !== "string") return false;
  const [address, prefix, extra] = value.trim().split("/");
  const version = isIP(address);
  if (!version || extra !== undefined) return false;
  if (prefix === undefined) return true;
  if (!/^\d+$/.test(prefix)) return false;
  const bits = Number(prefix);
  return bits >= 0 && bits <= (version === 4 ? 32 : 128);
}

function unknownKeys(value, allowed) {
  return Object.keys(value).find((key) => !allowed.includes(key)) || "";
}
