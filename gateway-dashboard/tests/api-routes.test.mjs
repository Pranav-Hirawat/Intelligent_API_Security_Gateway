// The console's API against a real Redis and Postgres. Skipped unless
// IASG_TEST_DASHBOARD_REDIS (host:port) names a Redis whose database 0 may be
// flushed; the Postgres half also needs IASG_TEST_POSTGRES_URL.
import assert from "node:assert/strict";
import test from "node:test";

const target = process.env.IASG_TEST_DASHBOARD_REDIS;
const pgUrl = process.env.IASG_TEST_POSTGRES_URL;
const skip = target ? false : "set IASG_TEST_DASHBOARD_REDIS to run the API route tests";

let redis, route, post, params;
if (target) {
  const [host, port] = target.split(":");
  process.env.REDIS_HOST = host;
  process.env.REDIS_PORT = port;
  if (pgUrl) process.env.IASG_POSTGRES_URL = pgUrl;
  else delete process.env.IASG_POSTGRES_URL;
  ({ route, post, params } = await import("./support/routes.mjs"));
  redis = await (await import("../lib/redis.js")).getRedis();
}

async function fresh() {
  await redis.flushDb();
  // Groups the control plane creates once at startup and a reset must keep.
  for (const [stream, group] of [["iasg:events", "iasg-agent"], ["iasg_overrides", "iasg-overrides"]]) {
    await redis.xGroupCreate(stream, group, "0", { MKSTREAM: true });
    await redis.xAdd(stream, "*", { event: "{}" });
  }
  await redis.hSet("iasg:stats", { requests: "5" });
  await redis.zAdd("iasg:attackers", { score: 3, value: "203.0.113.9" });
  await redis.set("iasg:ip:203.0.113.9:latest", "{}");
  await redis.set("campaign:1", JSON.stringify({ campaign_id: "1", type: "Brute Force", ips: ["203.0.113.9"] }));
  await redis.set("campaign:next_id", "1");
  await redis.set("feedback:Brute Force", '{"up":1}');
  await redis.set("policy:203.0.113.9", JSON.stringify({ action: "temp_block", policy_id: "p-1", target_identity: "203.0.113.9" }), { EX: 600 });
  await redis.set("policy:203.0.113.9:abcd", JSON.stringify({ action: "throttle", policy_id: "p-2" }), { EX: 600 });
  await redis.set("policy:203.0.113.10", JSON.stringify({ action: "throttle", policy_id: "p-3" }), { EX: 600 });
}

async function groups(stream) {
  return (await redis.xInfoGroups(stream)).map((g) => g.name);
}

async function schema() {
  const { getPool } = await import("../lib/postgres.js");
  const pool = getPool();
  // The control plane owns the real schema; these are the tables the admin
  // routes empty, which is all they need to exist.
  for (const table of ["policy_audit", "policy_recommendations", "endpoint_baselines", "campaigns", "feedback"]) {
    await pool.query(`CREATE TABLE IF NOT EXISTS ${table} (id int)`);
    await pool.query(`TRUNCATE ${table}`);
  }
  await pool.query("CREATE SEQUENCE IF NOT EXISTS campaign_id_seq");
  await pool.query("INSERT INTO campaigns (id) VALUES (1), (2)");
  await pool.query("INSERT INTO feedback (id) VALUES (1)");
  return pool;
}

test.after(async () => {
  if (redis) await redis.quit();
  if (pgUrl && target) await (await import("../lib/postgres.js")).getPool().end();
});

test("reset clears history but keeps consumer groups and live policy", { skip }, async () => {
  await fresh();
  const { POST } = await route("admin/reset");

  assert.equal((await POST(post({}))).status, 400, "an unconfirmed reset must do nothing");
  assert.equal(await redis.exists("iasg:stats"), 1);

  const res = await POST(post({ confirm: "reset" }));
  const body = await res.json();
  assert.equal(res.status, 200, JSON.stringify(body));

  assert.equal(await redis.xLen("iasg:events"), 0);
  // DEL on a stream drops its groups and leaves the agent failing NOGROUP.
  assert.deepEqual(await groups("iasg:events"), ["iasg-agent"]);
  assert.deepEqual(await groups("iasg_overrides"), ["iasg-overrides"]);
  for (const gone of ["iasg:stats", "iasg:attackers", "iasg:ip:203.0.113.9:latest", "campaign:1", "campaign:next_id", "feedback:Brute Force"]) {
    assert.equal(await redis.exists(gone), 0, `${gone} survived a reset`);
  }
  // Clearing history and lifting live blocks are different actions.
  assert.equal(await redis.exists("policy:203.0.113.9"), 1);
  assert.ok(Number(await redis.get("iasg:reset_at")) > 0, "no reset watermark was written");
});

test("clear campaigns keeps raw events and live policy", { skip }, async () => {
  await fresh();
  const { POST } = await route("admin/clear-campaigns");

  assert.equal((await POST(post({ confirm: "reset" }))).status, 400);
  const res = await POST(post({ confirm: "clear" }));
  const body = await res.json();
  assert.equal(res.status, 200, JSON.stringify(body));
  assert.equal(body.redisKeysRemoved, 3);

  assert.equal(await redis.exists("campaign:1"), 0);
  assert.equal(await redis.exists("feedback:Brute Force"), 0);
  assert.equal(await redis.xLen("iasg:events"), 1, "raw events were touched");
  assert.equal(await redis.exists("iasg:stats"), 1);
  assert.equal(await redis.exists("policy:203.0.113.9"), 1);
});

test("admin routes empty the durable record in one go", { skip: skip || (pgUrl ? false : "set IASG_TEST_POSTGRES_URL") }, async () => {
  await fresh();
  const pool = await schema();
  const clear = await (await route("admin/clear-campaigns")).POST(post({ confirm: "clear" }));
  const cleared = await clear.json();
  assert.deepEqual(cleared.postgres, { ok: true, cleared: { campaigns: 2, feedback: 1 } });
  assert.equal(cleared.campaigns, 2);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM campaigns")).rows[0].n, 0);

  await pool.query("INSERT INTO policy_audit (id) VALUES (1)");
  const reset = await (await route("admin/reset")).POST(post({ confirm: "reset" }));
  const body = await reset.json();
  assert.equal(body.postgres.ok, true);
  assert.equal(body.postgres.cleared.policy_audit, 1);
});

test("an override goes to the stream the agent reads, as the session's user", { skip }, async () => {
  await fresh();
  const { POST } = await route("overrides");
  const bad = [
    [{ action: "throttle" }, /ip is required/],
    [{ ip: "203.0.113.5", action: "allow" }, /action must be one of/],
    [{ ip: "not-an-ip", action: "throttle" }, /not an IP address/],
  ];
  for (const [body, error] of bad) {
    const res = await POST(post(body));
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, error);
  }
  assert.equal((await POST(post("{nope"))).status, 400);

  const res = await POST(post({ ip: "203.0.113.5", action: "throttle", actor: "mallory", reason: "r".repeat(400) }));
  assert.equal(res.status, 200);
  const [, last] = (await redis.xRange("iasg_overrides", "-", "+")).map((e) => e.message);
  assert.equal(last.ip, "203.0.113.5");
  // Who did it comes from the session, never the request body.
  assert.equal(last.actor, "operator");
  assert.equal(last.reason.length, 280);
});

test("settings: the page edits what the gateway published, and nothing else", { skip }, async () => {
  await fresh();
  const { GET, POST, DELETE } = await route("settings");

  const none = await GET();
  assert.equal(none.status, 503, "with nothing published there is nothing trustworthy to edit");

  await redis.set("iasg:settings:effective", JSON.stringify({
    source: "file",
    adaptive_rate_limit: { burst: 20 },
    rate_limit: { enabled: true, requests_per_minute: 100 },
  }));
  const got = await (await GET()).json();
  assert.equal(got.source, "file");
  assert.ok(got.settings.rate_limit && !got.settings.adaptive_rate_limit, "structural settings must be read-only");
  assert.ok(got.readOnly.adaptive_rate_limit);

  assert.equal((await POST(post({ settings: got.settings }))).status, 400, "unconfirmed");
  const partial = await POST(post({ confirm: "apply", settings: got.settings }));
  assert.equal(partial.status, 400, "a partial block would zero every missing detector");
  assert.equal(await redis.exists("iasg:settings"), 0);

  await redis.set("iasg:settings:effective", "{not json");
  assert.equal((await GET()).status, 502);

  await redis.set("iasg:settings", "{}");
  const reverted = await (await DELETE()).json();
  assert.equal(reverted.reverted, true);
  assert.equal(await redis.exists("iasg:settings"), 0);
});

test("deleting a policy lifts every key for that address and no other", { skip }, async () => {
  await fresh();
  const { DELETE } = await route("policies/[address]");
  assert.equal((await DELETE(new Request("http://x"), params({ address: "nope" }))).status, 400);

  const res = await DELETE(new Request("http://x"), params({ address: "203.0.113.9" }));
  const body = await res.json();
  assert.equal(body.removed, true);
  assert.equal(await redis.exists("policy:203.0.113.9"), 0);
  assert.equal(await redis.exists("policy:203.0.113.9:abcd"), 0);
  assert.equal(await redis.exists("policy:203.0.113.10"), 1, "another address's block was lifted");

  const again = await (await DELETE(new Request("http://x"), params({ address: "203.0.113.9" }))).json();
  assert.equal(again.removed, false);
});

test("the address view only shows that address", { skip }, async () => {
  await fresh();
  await redis.xAdd("iasg:events", "*", { event: JSON.stringify({ ip: "203.0.113.9", path: "/a", fired: ["sql_injection"] }) });
  await redis.xAdd("iasg:events", "*", { event: JSON.stringify({ ip: "203.0.113.50", path: "/b" }) });
  const { GET } = await route("ip/[address]");
  const res = await GET(new Request("http://x"), params({ address: "203.0.113.9" }));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(JSON.stringify(body).includes("203.0.113.9"));
  assert.ok(!JSON.stringify(body).includes("203.0.113.50"), "another address's events leaked in");
});

// Before the control plane has ever run there is no campaign_id_seq. Resetting
// it used to fail inside the transaction with the error swallowed, so COMMIT
// became a rollback and the route reported rows cleared that were still there.
test("a clear before the control plane ever ran really clears", {
  skip: skip || (pgUrl ? false : "set IASG_TEST_POSTGRES_URL"),
}, async () => {
  await fresh();
  const pool = await schema();
  await pool.query("DROP SEQUENCE IF EXISTS campaign_id_seq");
  const body = await (await (await route("admin/clear-campaigns")).POST(post({ confirm: "clear" }))).json();
  assert.equal(body.postgres.ok, true);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM campaigns")).rows[0].n, 0);
});

async function addEvents(rows) {
  const ids = [];
  for (const row of rows) {
    ids.push(await redis.xAdd("iasg:events", "*", { event: JSON.stringify({ method: "GET", path: "/api/products", status: 200, fired: [], ...row }) }));
  }
  return ids;
}

const eventsPage = async (query) => (await (await route("events")).GET(new Request(`http://console/api/events?${query}`))).json();

test("paging through events returns every one exactly once, newest first", { skip }, async () => {
  await redis.flushDb();
  const ids = await addEvents(Array.from({ length: 23 }, (_, i) => ({ ip: `203.0.113.${i % 3}` })));

  const seen = [];
  let cursor = "";
  for (let page = 0; page < 10; page++) {
    const body = await eventsPage(`limit=5${cursor ? `&before=${cursor}` : ""}`);
    assert.equal(body.total, 23);
    seen.push(...body.events.map((e) => e.id));
    cursor = body.cursor;
    if (!cursor) break;
  }
  assert.deepEqual(seen, [...ids].reverse());
});

// The stream has no index on address, so a filter scans. The scan per request
// is bounded, and the cursor must carry it on to an address that only
// appears far back.
test("a rare address deep in the stream is reached one bounded page at a time", { skip }, async () => {
  await redis.flushDb();
  const [oldest] = await addEvents([{ ip: "198.51.100.77" }]);
  await addEvents(Array.from({ length: 40 }, () => ({ ip: "203.0.113.1" })));

  let cursor = "";
  let found = [];
  let requests = 0;
  while (!found.length && requests < 10) {
    const body = await eventsPage(`limit=2&ip=198.51.100.77${cursor ? `&before=${cursor}` : ""}`);
    requests += 1;
    assert.equal(body.ip, "198.51.100.77");
    found = body.events;
    cursor = body.cursor;
    if (!found.length) assert.ok(cursor, "the scan stopped with the address still unread");
  }
  assert.deepEqual(found.map((e) => e.id), [oldest]);
  assert.ok(requests > 1, "one request scanned the whole stream; the bound is not holding");
});

test("a malformed address filter shows everything rather than an error", { skip }, async () => {
  await redis.flushDb();
  await addEvents([{ ip: "203.0.113.1" }, { ip: "203.0.113.2" }]);
  const body = await eventsPage("ip=not-an-ip&limit=-4");
  assert.equal(body.ip, null);
  assert.equal(body.events.length, 2);
});

test("overview: health probes hidden, private sources never looked up, loudest attacker first", { skip }, async () => {
  await redis.flushDb();
  await addEvents([
    { ip: "127.0.0.1", path: "/api/health", status: 200, userAgent: "IASG-Docker-Healthcheck" },
    { ip: "10.0.0.8" },
    { ip: "198.51.100.40", fired: ["sql_injection"] },
    { ip: "198.51.100.41" },
    { ip: "198.51.100.41" },
    { ip: "198.51.100.41", fired: ["api_flooding"] },
    { ip: "198.51.100.40", fired: ["sql_injection"] },
  ]);
  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    sent.push(options.body ? JSON.parse(options.body) : String(url));
    return { ok: false, json: async () => null };
  };
  try {
    const body = await (await (await route("overview")).GET()).json();
    assert.equal(body.redis, true);
    assert.ok(!body.events.some((e) => e.path === "/api/health"), "a routine probe was shown");
    assert.equal(body.stats.requests, 6);
    assert.deepEqual(body.attackers, [{ ip: "198.51.100.40", alerts: 2 }, { ip: "198.51.100.41", alerts: 1 }]);
    const lookedUp = sent.flat().filter((item) => typeof item === "string" && item.includes("."));
    assert.ok(!lookedUp.includes("10.0.0.8"), `a private address left the machine: ${JSON.stringify(sent)}`);
    assert.equal(body.sources.find((s) => s.ip === "10.0.0.8").city, "Private network");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("the gateway's attacker board wins over the visible window", { skip }, async () => {
  await redis.flushDb();
  await addEvents([{ ip: "198.51.100.50", fired: ["sql_injection"] }]);
  await redis.zAdd("iasg:attackers", [{ score: 9, value: "198.51.100.60" }]);
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, json: async () => null });
  try {
    const body = await (await (await route("overview")).GET()).json();
    assert.deepEqual(body.attackers, [{ ip: "198.51.100.60", alerts: 9 }]);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("campaigns: counts what is active and says whether the agent is alive", { skip }, async () => {
  await redis.flushDb();
  await redis.set("campaign:1", JSON.stringify({ campaign_id: "1", status: "active" }));
  await redis.set("campaign:2", JSON.stringify({ campaign_id: "2", status: "contained" }));
  await redis.set("iasg:heartbeat", JSON.stringify({ at: new Date().toISOString() }));
  const body = await (await (await route("campaigns")).GET()).json();
  assert.equal(body.redis, true);
  assert.equal(body.active, 1);
  assert.equal(body.campaigns.length, 2);
  assert.equal(body.heartbeat.alive, true);
});
