// How the console names and shows what the gateway reported. These are shared
// by every page, so a wrong label here is wrong everywhere at once.
import assert from "node:assert/strict";
import test from "node:test";

import {
  actionLabel, canonicalSignals, clampRiskScore, formatTime, formatTtl, isValidIp,
  matchesEvent, normalizeAction, requestHistogram, riskTone, signalMeta,
} from "../app/ui/format.js";

test("older signal names show under today's name, once", () => {
  assert.equal(signalMeta("path_traversal").label, "Path traversal & enumeration");
  assert.equal(signalMeta("path_traversal+enumeration").label, "Path traversal & enumeration");
  assert.deepEqual(
    canonicalSignals(["path_traversal", "enumeration", "sql_injection", "enumeration_path_traversal"]),
    ["enumeration_path_traversal", "sql_injection"],
  );
  assert.deepEqual(canonicalSignals(undefined), []);
});

test("a signal the console does not know is shown by its own name, not hidden", () => {
  assert.deepEqual(signalMeta("future_detector"), { label: "future_detector", color: "var(--muted)" });
});

test("both spellings of a temporary block read the same", () => {
  assert.equal(normalizeAction("temporary_block"), "temp_block");
  assert.equal(actionLabel("temporary_block"), "Temporary block");
  assert.equal(actionLabel("temp_block"), "Temporary block");
  assert.equal(actionLabel(""), "No action");
  assert.equal(actionLabel("rate_limited"), "rate limited");
});

test("risk is bounded to 0..100 and toned at 30 and 70", () => {
  assert.deepEqual([-5, 12.4, 250, "x", null].map(clampRiskScore), [0, 12, 100, 0, 0]);
  assert.deepEqual([0, 29, 30, 69, 70, 100].map(riskTone), ["low", "low", "mid", "mid", "high", "high"]);
});

test("a policy's remaining life reads in seconds, then minutes", () => {
  assert.equal(formatTtl(null), "no expiry");
  assert.equal(formatTtl(-1), "no expiry");
  assert.equal(formatTtl(45), "45s left");
  assert.equal(formatTtl(900), "15m left");
});

test("times are shown in IST, and a bad time as a dash", () => {
  assert.equal(formatTime("2026-09-25T10:00:05Z"), "15:30:05");
  assert.equal(formatTime(""), "-");
  assert.equal(formatTime("not a time"), "-");
});

test("the address filter accepts addresses and nothing else", () => {
  for (const ip of ["", " ", "203.0.113.5", "2001:db8::1", "::1"]) assert.ok(isValidIp(ip), ip);
  for (const ip of ["256.1.1.1", "203.0.113", "hello", "1.2.3.4; DROP"]) assert.ok(!isValidIp(ip), ip);
});

test("the request histogram keeps every event, newest on the right", () => {
  const at = (minutesAgo) => new Date(Date.UTC(2026, 8, 25, 10, 0) - minutesAgo * 60_000).toISOString();
  const events = [at(0), at(0), at(1), at(5), at(40), "garbage"].map((ts) => ({ ts }));
  const buckets = requestHistogram(events);
  assert.equal(buckets.length, 16);
  assert.equal(buckets[15], 2);
  assert.equal(buckets[14], 1);
  assert.equal(buckets[10], 1);
  assert.equal(buckets[0], 1, "an event older than the window lands in the oldest bucket");
  assert.equal(buckets.reduce((a, b) => a + b, 0), 5, "only the unreadable time was dropped");
  assert.deepEqual(requestHistogram([]), Array(16).fill(0));
  assert.deepEqual(requestHistogram([{ ts: "garbage" }]), Array(16).fill(0));
});

test("the search box matches address, path, method, user agent or signal name", () => {
  const event = { ip: "203.0.113.5", path: "/api/Login", method: "POST", userAgent: "curl/8.4", fired: ["sql_injection"] };
  for (const needle of ["", "  ", "113.5", "login", "post", "CURL", "sql inj"]) {
    assert.ok(matchesEvent(event, needle), needle);
  }
  assert.ok(!matchesEvent(event, "pos"), "method must match whole");
  assert.ok(!matchesEvent(event, "flooding"));
  assert.ok(!matchesEvent({}, "x"));
});
