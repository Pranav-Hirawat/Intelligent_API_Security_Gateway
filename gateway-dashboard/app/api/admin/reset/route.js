import { truncateTables } from "@/lib/postgres";
import { scanKeys } from "@/lib/plane";
import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";

export const dynamic = "force-dynamic";

/**
 * Reset the console to a clean slate for a fresh demo.
 *
 * Clears two things:
 *
 *   Postgres  the durable record -- campaigns and the agent's learned
 *             feedback. This is what the History page reads.
 *   Redis     the live telemetry the gateway has accumulated -- the event
 *             stream, the running stats, the top-attacker board, the per-IP
 *             latest, the campaign and feedback keys, and the alert and
 *             override streams. This is what Overview, Events and Campaigns
 *             read, so without it a "reset" would still show the old numbers.
 *
 * What it deliberately does NOT touch:
 *
 *   policy:*        Active enforcement. A block that is running should keep
 *                   running; it expires on its own. Deleting these keys would
 *                   be lifting live blocks, which is a different action from
 *                   clearing history and should be a deliberate one.
 *   iasg:heartbeat  The agent's liveness. Clearing it would make a running
 *                   control plane look dead until its next cycle.
 *   consumer groups The streams are trimmed rather than deleted, so the groups
 *                   the control plane reads through survive. See REDIS_STREAMS.
 *
 * Asks the caller to name the thing being destroyed, so a mis-click cannot do
 * it. Postgres and Redis are handled independently: if only one is available,
 * the reset still clears what it can and reports the rest.
 */

// Reset together or not at all: feedback refers to campaign types, so keeping
// one without the other leaves the agent learning from a record that is gone.
const TABLES = [
  "policy_audit", "policy_recommendations", "endpoint_baselines",
  "campaigns", "feedback",
];

// Streams the control plane holds consumer groups on. These are TRIMMED, never
// deleted: deleting a stream key deletes its consumer groups with it, and the
// agent creates those groups once at startup, not per cycle. A reset that
// deleted them left every later cycle failing with
//
//   NOGROUP No such key 'iasg_overrides' or consumer group 'iasg-overrides'
//
// until the control plane was restarted by hand. Trimming to zero empties the
// stream and leaves the group in place, which is what a reset actually wants.
const REDIS_STREAMS = [
  "iasg:events", // group iasg-agent, read by the evidence consumer
  "iasg:arrivals", // group iasg-windowing, read by completed-window analysis
  "iasg:telemetry:health",
  process.env.IASG_OVERRIDE_STREAM || "iasg_overrides", // group iasg-overrides
  "iasg_alerts",
];

// Fixed live keys the gateway writes. Plain values, safe to delete outright.
const REDIS_KEYS = ["iasg:stats", "iasg:attackers"];

// Set before the streams are trimmed below, for the same reason
// clear-campaigns sets it first: a control-plane cycle already mid-flight
// when this runs could still write a campaign from evidence it read a
// moment ago. Trimming iasg:events already removes that evidence for future
// cycles, but the watermark closes the same narrow window belt-and-suspenders
// -- see control-plane's EvidenceConsumer, which refuses to correlate
// anything with a stream id older than this.
const RESET_WATERMARK_KEY = process.env.IASG_RESET_WATERMARK_KEY || "iasg:reset_at";

// Key families to sweep. campaign:* includes the campaign:next_id counter, so
// numbering restarts with the Postgres sequence.
const REDIS_PATTERNS = ["campaign:*", "feedback:*", "iasg:ip:*"];

const clearPostgres = () => truncateTables(TABLES);

async function clearRedis() {
  let redis;
  try {
    redis = await getRedis();
  } catch (err) {
    return { ok: false, reason: err.message };
  }

  try {
    await redis.set(RESET_WATERMARK_KEY, String(Date.now()));

    // Empty the streams without dropping their consumer groups.
    let trimmed = 0;
    for (const stream of REDIS_STREAMS) {
      // XTRIM on a key that does not exist is a no-op, so no need to check.
      trimmed += await redis.xTrim(stream, "MAXLEN", 0);
    }

    const keys = [...REDIS_KEYS];
    for (const pattern of REDIS_PATTERNS) keys.push(...(await scanKeys(redis, pattern)));
    // DEL ignores keys that are not there, so no need to filter first.
    const removed = keys.length ? await redis.del(keys) : 0;
    return { ok: true, removed, trimmed };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}

export async function POST(request) {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  let body = {};
  try {
    body = await request.json();
  } catch {
    /* an empty body fails the confirmation below, which is the right answer */
  }

  if (body.confirm !== "reset") {
    return Response.json({ ok: false, error: 'type "reset" to confirm' }, { status: 400 });
  }

  const [postgres, redis] = await Promise.all([clearPostgres(), clearRedis()]);

  console.log(
    `[admin] ${gate.user.username} reset the console:`,
    `postgres=${postgres.ok ? JSON.stringify(postgres.cleared) : postgres.reason}`,
    `redis=${redis.ok ? `${redis.removed} keys, ${redis.trimmed} stream entries` : redis.reason}`,
  );

  // A reset that reached neither store did nothing, and should say so rather
  // than report success.
  if (!postgres.ok && !redis.ok) {
    return Response.json(
      { ok: false, error: `nothing cleared -- postgres: ${postgres.reason}; redis: ${redis.reason}` },
      { status: 500 },
    );
  }

  return Response.json({ ok: true, postgres, redis });
}
