// Where attackers are drawn on the map. Lookups go to an outside service, so
// what may be sent there matters as much as what comes back.
import assert from "node:assert/strict";
import test from "node:test";

import { isPrivateIP, lookupGeo, lookupSelfGeo, summarizeSources } from "../lib/geo.js";

const realFetch = globalThis.fetch;
function stubFetch(handler) {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), body: options.body ? JSON.parse(options.body) : null });
    return handler(url, options);
  };
  return calls;
}
const json = (value, ok = true) => ({ ok, json: async () => value });
test.afterEach(() => {
  globalThis.fetch = realFetch;
});

test("addresses that name no one on the internet are private", () => {
  for (const ip of [
    "", "localhost", "127.0.0.1", "127.8.9.10", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255",
    "192.168.1.1", "169.254.10.10", "100.64.0.1", "0.0.0.0", "fd12:3456::1", "fe80::1",
    "::ffff:10.0.0.5", "::", "not-an-address",
  ]) {
    assert.equal(isPrivateIP(ip), true, ip);
  }
  for (const ip of ["8.8.8.8", "172.15.0.1", "172.32.0.1", "203.0.113.5", "2001:4860:4860::8888", "::ffff:8.8.8.8"]) {
    assert.equal(isPrivateIP(ip), false, ip);
  }
});

test("a private address is never sent to the lookup service", async () => {
  const calls = stubFetch(async () => json([]));
  await lookupGeo(["10.0.0.5", "fd00::7", "100.64.3.3", "192.168.0.9"]);
  assert.equal(calls.length, 0, `sent: ${JSON.stringify(calls)}`);
});

test("each public address is looked up once and then remembered", async () => {
  const calls = stubFetch(async (_url, options) =>
    json(JSON.parse(options.body).map((ip) => ({ query: ip, status: "success", lat: 1, lon: 2, city: "X" }))),
  );
  const first = await lookupGeo(["198.51.100.10", "198.51.100.10", "198.51.100.11", "10.0.0.1"]);
  assert.deepEqual(calls[0].body, ["198.51.100.10", "198.51.100.11"]);
  assert.equal(first["198.51.100.10"].city, "X");
  assert.ok(!("10.0.0.1" in first), "a private address was included in the answer");

  await lookupGeo(["198.51.100.10"]);
  assert.equal(calls.length, 1, "a cached address was looked up again");
});

test("a failed lookup leaves the map empty rather than failing the page", async () => {
  stubFetch(async () => {
    throw new Error("offline");
  });
  assert.deepEqual(await lookupGeo(["198.51.100.20"]), { "198.51.100.20": null });

  stubFetch(async () => json(null, false));
  assert.deepEqual(await lookupGeo(["198.51.100.21"]), { "198.51.100.21": null });
});

test("an address the service could not place is remembered as unplaceable", async () => {
  const calls = stubFetch(async () => json([{ query: "198.51.100.30", status: "fail" }]));
  const first = await lookupGeo(["198.51.100.30"]);
  assert.deepEqual(first["198.51.100.30"], { private: false });
  await lookupGeo(["198.51.100.30"]);
  assert.equal(calls.length, 1);
});

test("the lab's own location is looked up once, and a failure is remembered too", async () => {
  const calls = stubFetch(async () => json({ status: "fail" }));
  assert.equal(await lookupSelfGeo(), null);
  assert.equal(await lookupSelfGeo(), null);
  assert.equal(calls.length, 1);
});

test("sources are ranked by requests, with alerts and the worst risk kept", () => {
  const rows = summarizeSources([
    { ip: "198.51.100.1", fired: ["sql_injection"], riskScore: 250 },
    { ip: "198.51.100.2", fired: [] },
    { ip: "198.51.100.2", fired: [], riskScore: "n/a" },
    { ip: "198.51.100.2", fired: ["api_flooding"], riskScore: 40.6 },
    { fired: ["sql_injection"] },
  ]);
  assert.deepEqual(rows, [
    { ip: "198.51.100.2", requests: 3, alerts: 1, lastRisk: 41 },
    { ip: "198.51.100.1", requests: 1, alerts: 1, lastRisk: 100 },
  ]);
});
