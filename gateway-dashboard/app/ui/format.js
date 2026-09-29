const SIGNAL_META = {
  api_flooding: { label: "API flooding", color: "var(--sig-flood)" },
  sql_injection: { label: "SQL injection", color: "var(--sig-sqli)" },
  consecutive_failed_logins: { label: "Brute force", color: "var(--sig-brute)" },
  unknown_route_scanning: { label: "Unknown-route scanning", color: "var(--sig-spray)" },
  object_enumeration: { label: "Object ID enumeration (BOLA)", color: "var(--sig-objenum)" },
  ownership_violation: { label: "Ownership check (BOLA)", color: "var(--sig-ownership)" },
  enumeration_path_traversal: { label: "Path traversal & enumeration", color: "var(--sig-enum-trav)" },
  ip_reputation: { label: "Known bad addresses", color: "var(--sig-reputation)" },
};

const LEGACY_SIGNAL_ALIASES = {
  path_traversal: "enumeration_path_traversal",
  enumeration: "enumeration_path_traversal",
  "path_traversal+enumeration": "enumeration_path_traversal",
};

function canonicalSignalId(name) {
  return LEGACY_SIGNAL_ALIASES[name] || name;
}

export function signalMeta(name) {
  return SIGNAL_META[canonicalSignalId(name)] || { label: name, color: "var(--muted)" };
}

export function canonicalSignals(fired) {
  const seen = new Set();
  const out = [];
  for (const name of fired || []) {
    const id = canonicalSignalId(name);
    if (!seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

export const SIGNAL_OPTIONS = Object.values(SIGNAL_META).map((signal) => signal.label);
export const LADDER = ["monitor", "throttle", "temp_block", "escalate"];

export function normalizeAction(action) {
  return action === "temporary_block" ? "temp_block" : action;
}

export const ACTION_TONE = {
  monitor: "low",
  throttle: "mid",
  rate_limited: "mid",
  temp_block: "high",
  temporary_block: "high",
  escalate: "high",
};

const ACTION_LABELS = {
  monitor: "Monitor",
  throttle: "Throttle",
  temp_block: "Temporary block",
  escalate: "Escalate",
  rate_limited: "Rate limited",
  ownership_refused: "Refused: not the owner",
  authentication_required: "Refused: login required",
  body_too_large: "Refused: body too large",
  body_unreadable: "Refused: unreadable body",
};

// Refusals the gateway makes on its own, with no policy behind them. The event
// still carries decision "allow" -- no policy acted -- but the client was
// refused, and showing "allow" beside a 404 the gateway wrote reads as a
// missing object that nothing stopped.
const GATEWAY_REFUSALS = new Set([
  "ownership_refused", "authentication_required", "body_too_large", "body_unreadable",
]);

/** What happened to a request: the policy's action, or the gateway's own refusal. */
export function eventAction(event = {}) {
  const decision = event.decision || "allow";
  if (decision === "allow" && GATEWAY_REFUSALS.has(event.gatewayReason)) return event.gatewayReason;
  return decision;
}

export function actionLabel(action) {
  if (!action) return "No action";
  const id = normalizeAction(action);
  return ACTION_LABELS[id] || id.replace(/_/g, " ");
}

export function riskTone(score) {
  if (score >= 70) return "high";
  if (score >= 30) return "mid";
  return "low";
}

export function clampRiskScore(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) return 0;
  return Math.min(100, Math.max(0, Math.round(score)));
}

export function formatTtl(seconds) {
  if (seconds == null || seconds < 0) return "no expiry";
  if (seconds < 60) return `${seconds}s left`;
  return `${Math.round(seconds / 60)}m left`;
}

export const DISPLAY_TIME_ZONE = "Asia/Kolkata";
export const DISPLAY_TIME_ZONE_LABEL = "IST";
const IST_TIME_FORMATTER = new Intl.DateTimeFormat("en-IN", {
  timeZone: DISPLAY_TIME_ZONE,
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
});

export function formatTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return IST_TIME_FORMATTER.format(date);
}

export function isValidIp(value) {
  const ip = (value || "").trim();
  if (!ip) return true;
  const ipv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)
    && ip.split(".").every((octet) => Number(octet) <= 255);
  const ipv6 = /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(":");
  return ipv4 || ipv6;
}

export function requestHistogram(events) {
  const buckets = Array.from({ length: 16 }, () => 0);
  if (!events.length) return buckets;
  const newest = new Date(events[0].ts).getTime();
  if (Number.isNaN(newest)) return buckets;
  const span = 16 * 60 * 1000;
  for (const event of events) {
    const time = new Date(event.ts).getTime();
    if (Number.isNaN(time)) continue;
    const index = Math.min(15, Math.max(0, Math.floor(((newest - time) / span) * 16)));
    buckets[15 - index] += 1;
  }
  return buckets;
}

export function matchesEvent(event, needle) {
  if (!needle) return true;
  const query = needle.trim().toLowerCase();
  if (!query) return true;
  return (
    event.ip?.toLowerCase().includes(query)
    || event.path?.toLowerCase().includes(query)
    || event.method?.toLowerCase() === query
    || event.userAgent?.toLowerCase().includes(query)
    || (event.fired || []).some((signal) => signalMeta(signal).label.toLowerCase().includes(query))
  );
}
