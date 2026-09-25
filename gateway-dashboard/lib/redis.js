import { createClient } from "redis";

const globalForRedis = globalThis;

export async function getRedis() {
  if (!globalForRedis.__iasgRedis) {
    const host = process.env.REDIS_HOST || "127.0.0.1";
    const port = process.env.REDIS_PORT || "6379";
    // Retrying forever is right for a connection that has worked and dropped,
    // and wrong for one that never came up: connect() would stay pending, and
    // every route awaiting it would hang until the browser gave up instead of
    // answering "redis unavailable". So the first connection gets one attempt,
    // and the next request tries again from scratch.
    let connected = false;
    const client = createClient({
      url: `redis://${host}:${port}`,
      // While a dropped connection is being retried, fail commands at once
      // rather than queueing them behind a reconnect that may never come.
      disableOfflineQueue: true,
      socket: {
        connectTimeout: 1500,
        reconnectStrategy: (retries, cause) => (connected ? Math.min(retries * 200, 2000) : cause),
      },
    });
    client.on("ready", () => {
      connected = true;
    });
    client.on("error", (err) => {
      console.error("redis:", err.message);
    });
    globalForRedis.__iasgRedis = client;
    globalForRedis.__iasgRedisReady = client.connect();
  }

  try {
    await globalForRedis.__iasgRedisReady;
  } catch (err) {
    globalForRedis.__iasgRedis = null;
    globalForRedis.__iasgRedisReady = null;
    throw err;
  }

  return globalForRedis.__iasgRedis;
}
