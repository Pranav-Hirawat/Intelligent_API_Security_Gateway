// Reading what the control plane wrote. The agent and the console are
// separate programs released separately, so every field here may be missing,
// malformed, or from an older version -- and a page must still render.
import assert from "node:assert/strict";
import test from "node:test";

import {
  coalescePolicies, readAlerts, readCampaigns, readHeartbeat, readLearned, readPolicies, readPolicyFor, scanKeys,
} from "../lib/plane.js";

// Just enough of a Redis client for these readers.
function fakeRedis(values = {}, { ttls = {}, alerts = null, batches = false } = {}) {
  const glob = (pattern) => new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);
  return {
    async *scanIterator({ MATCH }) {
      const keys = Object.keys(values).filter((key) => glob(MATCH).test(key));
      if (batches) yield keys;
      else yield* keys;
    },
    async mGet(keys) { return keys.map((key) => values[key] ?? null); },
    async get(key) { return values[key] ?? null; },
    async ttl(key) { return ttls[key] ?? -1; },
    async xRevRange() {
      if (alerts instanceof Error) throw alerts;
      return alerts || [];
    },
  };
}

test("keys are found whether the client yields one at a time or in batches", async () => {
  const values = { "policy:a": "1", "policy:b": "2", other: "3" };
  assert.deepEqual((await scanKeys(fakeRedis(values), "policy:*")).sort(), ["policy:a", "policy:b"]);
  assert.deepEqual((await scanKeys(fakeRedis(values, { batches: true }), "policy:*")).sort(), ["policy:a", "policy:b"]);
});

test("campaigns: active first, then most certain; the id counter and junk are skipped", async () => {
  const redis = fakeRedis({
    "campaign:next_id": "9",
    "campaign:1": JSON.stringify({ campaign_id: "1", status: "contained", confidence: 0.99 }),
    "campaign:2": JSON.stringify({ campaign_id: "2", confidence: 0.4 }),
    "campaign:3": JSON.stringify({ campaign_id: "3", status: "active", confidence: 0.9, ips: ["203.0.113.5"] }),
    "campaign:4": "{broken",
  });
  const campaigns = await readCampaigns(redis);
  assert.deepEqual(campaigns.map((c) => c.id), ["3", "2", "1"]);
  assert.equal(campaigns[1].type, "Unclassified Activity", "a missing type still gets a name");
  assert.equal(campaigns[1].rotations, 0);
  assert.deepEqual(await readCampaigns(fakeRedis({ "campaign:next_id": "1" })), []);
});

test("policies show what Redis says is left, and read both key shapes", async () => {
  const redis = fakeRedis(
    {
      "policy:203.0.113.5": JSON.stringify({ action: "temp_block", confidence: 0.6, policy_id: "p1" }),
      "policy:203.0.113.7:abcd": JSON.stringify({
        action: "throttle", confidence: 0.9, target_identity: "203.0.113.7",
        endpoint_scope: { method: "POST", route_template: "/api/login" },
      }),
      "policy:203.0.113.8": "{broken",
    },
    { ttls: { "policy:203.0.113.5": 120 } },
  );
  const policies = await readPolicies(redis);
  assert.deepEqual(policies.map((p) => p.ip), ["203.0.113.7", "203.0.113.5"]);
  assert.equal(policies[0].routeTemplate, "/api/login");
  assert.equal(policies[1].expiresIn, 120);
  assert.equal(policies[0].source, "agent", "an older policy with no source reads as the agent's");
  assert.equal((await readPolicyFor(redis, "203.0.113.5")).policyId, "p1");
  assert.equal(await readPolicyFor(redis, "198.51.100.1"), null);
  assert.deepEqual(await readPolicies(fakeRedis()), []);
});

test("policy rows combine endpoint and client scopes for one identity", () => {
  const policies = coalescePolicies([
    {
      policyId: "client", ip: "198.51.100.55", action: "throttle", confidence: 0.8,
      expiresIn: 420, method: "", routeTemplate: "",
    },
    {
      policyId: "login", ip: "198.51.100.55", action: "throttle", confidence: 0.88,
      expiresIn: 480, method: "POST", routeTemplate: "/api/login",
    },
  ]);

  assert.equal(policies.length, 1, "one incident must not render as duplicate policy rows");
  assert.equal(policies[0].policyCount, 2);
  assert.deepEqual(policies[0].scopes, ["Any request", "POST /api/login"]);
  assert.equal(policies[0].expiresIn, 420, "the earliest scope expiry must remain visible");
  assert.equal(policies[0].policyId, "login", "the primary policy still links back to its durable record");
});

test("alerts read from the stream, and a stream that does not exist yet is no alerts", async () => {
  const alerts = await readAlerts(fakeRedis({}, {
    alerts: [{ id: "1-0", message: { campaign_id: "4", confidence: "0.8", ip_count: "6", type: "Flood" } }],
  }));
  assert.deepEqual(alerts.map((a) => [a.campaignId, a.confidence, a.ipCount]), [["4", 0.8, 6]]);
  assert.deepEqual(await readAlerts(fakeRedis({}, { alerts: new Error("no such key") })), []);
});

test("learned corrections are ranked by strength, and an empty tally is not shown", async () => {
  const learned = await readLearned(fakeRedis({
    "feedback:Flood": JSON.stringify({ up: 1 }),
    "feedback:Recon": JSON.stringify({ up: 0, down: 3 }),
    "feedback:Quiet": JSON.stringify({}),
    "feedback:Broken": "{",
  }));
  assert.deepEqual(learned, [
    { type: "Recon", up: 0, down: 3, net: -3 },
    { type: "Flood", up: 1, down: 0, net: 1 },
  ]);
  assert.deepEqual(await readLearned(fakeRedis()), []);
});

test("a heartbeat older than two intervals is reported late, and none means stopped", async () => {
  const at = (secondsAgo) => new Date(Date.now() - secondsAgo * 1000).toISOString();

  assert.deepEqual(await readHeartbeat(fakeRedis()), { alive: false });
  assert.deepEqual(await readHeartbeat(fakeRedis({ "iasg:heartbeat": "{broken" })), { alive: false });

  const fresh = await readHeartbeat(fakeRedis({ "iasg:heartbeat": JSON.stringify({ at: at(10), interval_seconds: 30, evidence: 7 }) }));
  assert.equal(fresh.alive, true);
  assert.equal(fresh.late, false);
  assert.equal(fresh.lastCycle.evidence, 7);
  assert.equal(fresh.narrationProvider, "null");

  const late = await readHeartbeat(fakeRedis({ "iasg:heartbeat": JSON.stringify({ at: at(90) }) }));
  assert.equal(late.intervalSeconds, 30, "a missing interval defaults to the agent's own default");
  assert.equal(late.late, true);
});
