// How the console's Redis client behaves as Redis comes and goes. Uses a
// stand-in server that answers +OK to everything, so no real Redis is needed,
// and its own process, so the client singleton it exercises is its own.
import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";

delete process.env.IASG_POSTGRES_URL;
delete process.env.DATABASE_URL;

function standIn(port) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("data", (chunk) => {
      for (const _ of chunk.toString().matchAll(/(?:^|\r\n)\*\d+\r\n/g)) socket.write("+OK\r\n");
    });
  });
  return new Promise((resolve) =>
    server.listen(port, "127.0.0.1", () =>
      resolve({
        port: server.address().port,
        // Drop every client and stop listening, as a crashed Redis would.
        kill: () => new Promise((done) => {
          for (const s of sockets) s.destroy();
          server.close(done);
        }),
      }),
    ),
  );
}

// A port nothing is listening on, that a stand-in can take later.
const freePort = async () => {
  const probe = await standIn(0);
  await probe.kill();
  return probe.port;
};

const within = (ms, promise) =>
  Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error(`still pending after ${ms}ms`)), ms))]);

const port = await freePort();
process.env.REDIS_HOST = "127.0.0.1";
process.env.REDIS_PORT = String(port);
const { getRedis } = await import("../lib/redis.js");
const { route } = await import("./support/routes.mjs");

test("a Redis that was down at first is picked up once it starts", async () => {
  await assert.rejects(within(3000, getRedis()));

  const server = await standIn(port);
  try {
    const redis = await within(3000, getRedis());
    assert.equal(await redis.set("k", "v"), "OK");
  } finally {
    await server.kill();
  }
});

test("a connection that drops fails requests at once instead of queueing them", async () => {
  // The previous test left a client whose server has gone; it is now retrying.
  const res = await within(1000, (await route("campaigns")).GET());
  assert.equal((await res.json()).redis, false);
});

// A client left retrying would keep the process, and so the whole run, alive.
test.after(async () => {
  await globalThis.__iasgRedis?.disconnect().catch(() => {});
});
