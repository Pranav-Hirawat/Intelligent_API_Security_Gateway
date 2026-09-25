import { truncateTables } from "@/lib/postgres";
import { scanKeys } from "@/lib/plane";
import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";

export const dynamic = "force-dynamic";

/**
 * Clear campaigns -- narrower than "Reset console" (app/api/admin/reset).
 *
 * Clears:
 *
 *   Postgres  campaigns, and feedback (keyed by campaign_type -- a record of
 *             corrections the agent learned from campaigns of that type,
 *             meaningless once every campaign it could apply to is gone).
 *   Redis     the live campaign:* keys (including campaign:next_id, so
 *             numbering restarts with the Postgres sequence).
 *
 * Deliberately does NOT touch:
 *
 *   iasg:events, iasg:arrivals   Raw telemetry. Clearing campaigns is about
 *                                the agent's groupings, not the record of
 *                                what actually happened -- Events must show
 *                                the same history after this as before.
 *   policy:*                     Active enforcement. A block that is running
 *                                keeps running; it expires on its own. A
 *                                policy that names a now-gone campaign is
 *                                handled by the UI (campaign links are
 *                                already guarded against a missing target),
 *                                not by silently pulling the policy too.
 *   policy_recommendations,
 *   policy_audit,
 *   endpoint_baselines           The adaptive system's own state, unrelated
 *                                to campaign display.
 *
 * The reset watermark is written FIRST, before either store is touched. This
 * is what makes a concurrent control-plane cycle safe without a cross-process
 * lock: if a cycle is mid-flight right now and writes a new campaign from
 * evidence it already read before this request arrived, that write either
 * lands before the truncate/DEL below (and is deleted right along with
 * everything else) or after (and is evidence produced before the watermark,
 * so the NEXT cycle's correlation -- see control-plane's EvidenceConsumer --
 * already knows to ignore whatever produced it). Either way nothing from
 * before this moment can end up standing after it.
 */

const TABLES = ["campaigns", "feedback"];
const REDIS_PATTERNS = ["campaign:*", "feedback:*"];
const RESET_WATERMARK_KEY = process.env.IASG_RESET_WATERMARK_KEY || "iasg:reset_at";

const clearPostgres = () => truncateTables(TABLES, { cleared: {} });

async function clearRedisCampaigns(redis) {
  const keys = [];
  for (const pattern of REDIS_PATTERNS) keys.push(...(await scanKeys(redis, pattern)));
  const removed = keys.length ? await redis.del(keys) : 0;
  return { ok: true, removed };
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

  if (body.confirm !== "clear") {
    return Response.json({ ok: false, error: 'type "clear" to confirm' }, { status: 400 });
  }

  let redis;
  try {
    redis = await getRedis();
  } catch (err) {
    return Response.json({ ok: false, error: `redis unavailable: ${err.message}` }, { status: 503 });
  }

  // See the module comment: this ordering is what makes a concurrent
  // control-plane cycle safe.
  await redis.set(RESET_WATERMARK_KEY, String(Date.now()));

  let redisResult;
  try {
    redisResult = await clearRedisCampaigns(redis);
  } catch (err) {
    redisResult = { ok: false, reason: err.message, removed: 0 };
  }
  const postgres = await clearPostgres();

  const clearedCampaigns = postgres.ok ? postgres.cleared.campaigns || 0 : 0;
  const clearedFeedback = postgres.ok ? postgres.cleared.feedback || 0 : 0;

  console.log(
    `[admin] ${gate.user.username} cleared campaigns:`,
    `postgres=${postgres.ok ? JSON.stringify(postgres.cleared) : postgres.reason}`,
    `redis=${redisResult.ok ? `${redisResult.removed} keys` : redisResult.reason}`,
  );

  if (!postgres.ok && !redisResult.ok) {
    return Response.json(
      { ok: false, error: `nothing cleared -- postgres: ${postgres.reason}; redis: ${redisResult.reason}` },
      { status: 500 },
    );
  }

  return Response.json({
    ok: true,
    cleared: clearedCampaigns + clearedFeedback,
    campaigns: clearedCampaigns,
    feedback: clearedFeedback,
    redisKeysRemoved: redisResult.removed || 0,
    postgres,
    redis: redisResult,
  });
}
