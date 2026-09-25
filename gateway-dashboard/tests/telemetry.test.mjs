import assert from "node:assert/strict";
import test from "node:test";
import { isRoutineDockerHealthcheck, parseEventMessage, parseStats, withDerivedStats } from "../lib/telemetry.js";

test("only a successful loopback Docker probe is treated as routine", () => {
  assert.ok(isRoutineDockerHealthcheck({
    ip: "::1",
    method: "GET",
    path: "/api/health",
    status: 200,
    userAgent: "IASG-Docker-Healthcheck",
    fired: [],
  }));
});

test("an attack against the health endpoint remains visible", () => {
  assert.ok(!isRoutineDockerHealthcheck({
    ip: "203.0.113.48",
    method: "GET",
    path: "/api/health",
    status: 200,
    userAgent: "IASG-Docker-Healthcheck",
    fired: ["sql_injection"],
  }));
});

test("parseEventMessage keeps seq, the Req no. column reads it from", () => {
  const event = parseEventMessage({ event: JSON.stringify({ ip: "203.0.113.48", seq: 42 }) });
  assert.equal(event.seq, 42);
});

test("parseEventMessage tolerates an event from before seq existed", () => {
  const event = parseEventMessage({ event: JSON.stringify({ ip: "203.0.113.48" }) });
  assert.equal(event.seq, undefined);
});

test("the gateway's counters are read, typed and split by kind", () => {
  const stats = parseStats({
    requests: "12", alerts: "3", "decision:allow": "10", "decision:blocked": "2",
    "signal:sql_injection": "3", other: "9",
  });
  assert.deepEqual(stats, {
    requests: 12, alerts: 3,
    decisions: { allow: 10, blocked: 2 },
    signals: { sql_injection: 3 },
  });
  assert.deepEqual(parseStats(), { requests: 0, alerts: 0, decisions: {}, signals: {} });
});

// Zero is a claim. When evidence reached the stream without the gateway (the
// seeder, a replay, a restart), the console must not report zero requests
// above a screen full of attacks.
test("counters the gateway never published are filled in from visible events", () => {
  const events = [
    { fired: ["sql_injection"], status: 200 },
    { fired: ["sql_injection", "api_flooding"], decision: "blocked" },
    { fired: [], status: 404 },
    { status: 200 },
  ];
  const derived = withDerivedStats(parseStats({}), events);
  assert.equal(derived.requests, 4);
  assert.equal(derived.alerts, 2);
  assert.deepEqual(derived.signals, { sql_injection: 2, api_flooding: 1 });
  assert.deepEqual(derived.decisions, { allow: 2, blocked: 2 });
  assert.equal(derived.derived, true);
});

test("the gateway's own numbers always win over the visible window", () => {
  const published = parseStats({ requests: "500", alerts: "40", "decision:allow": "460", "signal:sql_injection": "40" });
  const derived = withDerivedStats(published, [{ fired: ["api_flooding"], status: 500 }]);
  assert.equal(derived.requests, 500);
  assert.equal(derived.alerts, 40);
  assert.deepEqual(derived.signals, { sql_injection: 40 });
  assert.deepEqual(derived.decisions, { allow: 460 });
  assert.equal(derived.derived, false, "a true lifetime count was labelled as a window");
});

test("a real gateway reporting zero alerts is not relabelled as derived", () => {
  const derived = withDerivedStats(parseStats({ requests: "5", alerts: "0" }), [{ fired: [] }, { fired: [] }]);
  assert.equal(derived.derived, false);
  assert.equal(withDerivedStats(parseStats({}), []).derived, false);
});

test("a stream entry that is not JSON is skipped, whatever form it arrives in", () => {
  assert.equal(parseEventMessage({ event: "{broken" }), null);
  assert.equal(parseEventMessage({}), null);
  assert.equal(parseEventMessage(), null);
  assert.equal(parseEventMessage({ event: Buffer.from('{"ip":"203.0.113.1"}') }).ip, "203.0.113.1");
});

test("an older probe with wget's own user agent is still recognised, anything else is not", () => {
  const probe = { ip: "127.0.0.1", method: "GET", path: "/api/health", status: 200, fired: [] };
  assert.ok(isRoutineDockerHealthcheck({ ...probe, userAgent: "Wget/1.21" }));
  assert.ok(isRoutineDockerHealthcheck({ ...probe, userAgent: "Wget" }));
  for (const change of [
    { userAgent: "curl/8" }, { ip: "203.0.113.5", userAgent: "Wget" }, { method: "POST", userAgent: "Wget" },
    { status: 500, userAgent: "Wget" }, { path: "/api/login", userAgent: "Wget" },
  ]) {
    assert.ok(!isRoutineDockerHealthcheck({ ...probe, ...change }), JSON.stringify(change));
  }
  assert.ok(!isRoutineDockerHealthcheck());
});
