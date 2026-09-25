// A dead Redis must produce a clear 503 from every route that needs it, never a
// hang or an unhandled crash. Runs in its own process, so pointing the client
// at a closed port here cannot affect any other test.
import assert from "node:assert/strict";
import test from "node:test";

process.env.REDIS_HOST = "127.0.0.1";
process.env.REDIS_PORT = "1";
delete process.env.IASG_POSTGRES_URL;
delete process.env.DATABASE_URL;

const { route, post, params } = await import("./support/routes.mjs");

test("a request that fails validation is refused without touching redis", async () => {
  assert.equal((await (await route("settings")).POST(post({ confirm: "nope" }))).status, 400);
  assert.equal((await (await route("admin/reset")).POST(post({}))).status, 400);
  assert.equal((await (await route("admin/clear-campaigns")).POST(post({ confirm: "reset" }))).status, 400);
  assert.equal((await (await route("overrides")).POST(post({ ip: "x", action: "throttle" }))).status, 400);
});

test("settings reports redis unavailable, keeping the message the page shows", async () => {
  const { GET, DELETE } = await route("settings");
  for (const res of [await GET(), await DELETE()]) {
    assert.equal(res.status, 503);
    assert.match((await res.json()).error, /^redis unavailable: /);
  }
});

test("reset with neither store reachable says nothing was cleared", async () => {
  const { POST } = await route("admin/reset");
  const res = await POST(post({ confirm: "reset" }));
  assert.equal(res.status, 500);
  assert.match((await res.json()).error, /^nothing cleared/);
});

test("clear campaigns reports redis unavailable", async () => {
  const { POST } = await route("admin/clear-campaigns");
  const res = await POST(post({ confirm: "clear" }));
  assert.equal(res.status, 503);
  assert.match((await res.json()).error, /^redis unavailable: /);
});

// The read routes degrade on purpose: 200 with redis:false, so a page shows
// empty panels and says why instead of breaking. What they must not do is hang.
test("reading routes answer at once, saying redis is unavailable", async () => {
  for (const [name, call] of [
    ["overview", (m) => m.GET()],
    ["events", (m) => m.GET(new Request("http://console/api/events"))],
    ["campaigns", (m) => m.GET()],
    ["ip/[address]", (m) => m.GET(new Request("http://console/x"), params({ address: "203.0.113.5" }))],
  ]) {
    const res = await call(await route(name));
    assert.equal(res.status, 200, name);
    assert.equal((await res.json()).redis, false, name);
  }
});

test("lifting a policy without redis fails rather than claiming it was lifted", async () => {
  const { DELETE } = await route("policies/[address]");
  const res = await DELETE(new Request("http://console/x"), params({ address: "203.0.113.5" }));
  assert.equal(res.status, 503);
});

test("an override for a real address cannot be queued without redis", async () => {
  const { POST } = await route("overrides");
  const res = await POST(post({ ip: "203.0.113.5", action: "throttle" }));
  assert.ok(res.status >= 500);
});
