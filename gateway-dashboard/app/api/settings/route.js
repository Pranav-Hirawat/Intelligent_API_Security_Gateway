import { getRedis } from "@/lib/redis";
import { parseJson } from "@/lib/plane";
import { require as requireRole } from "@/lib/auth";
import { splitSettings, validateSettings } from "@/lib/gateway-settings.mjs";

export const dynamic = "force-dynamic";

/**
 * Live enforcement settings.
 *
 * GET    what the gateway is running, and where it came from
 * POST   put an override in force
 * DELETE drop the override, returning the gateway to its config file
 *
 * Two keys are involved, and the difference between them matters:
 *
 *   iasg:settings            what the console asked for
 *   iasg:settings:effective  what the gateway is actually enforcing, written
 *                            by the gateway itself on every apply
 *
 * The page reads the effective key, never the requested one. If the gateway
 * refused an override -- a duration that will not parse, a CIDR that will not
 * -- the two disagree, and showing the request would tell the operator their
 * change is live when it is not. The effective key carries a TTL, so a gateway
 * that has stopped stops claiming to enforce anything.
 *
 * The section allowlist, the block.signals allowlist, and the validation
 * rules below all live in lib/gateway-settings.js, so they can be unit
 * tested without a Redis connection or an authenticated request.
 */

const OVERRIDE_KEY = "iasg:settings";
const EFFECTIVE_KEY = "iasg:settings:effective";

async function connect() {
  try {
    return { redis: await getRedis() };
  } catch (err) {
    return { unavailable: Response.json({ ok: false, error: `redis unavailable: ${err.message}` }, { status: 503 }) };
  }
}

export async function GET() {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  const { redis, unavailable } = await connect();
  if (unavailable) return unavailable;

  const [effectiveRaw, overrideRaw] = await Promise.all([
    redis.get(EFFECTIVE_KEY),
    redis.get(OVERRIDE_KEY),
  ]);

  if (!effectiveRaw) {
    // No gateway has published, so there is nothing trustworthy to edit. Saying
    // so beats rendering a form built from the override, which would let an
    // operator "change" settings nothing is reading.
    return Response.json({
      ok: false,
      error:
        "the gateway has not published its settings — it may be stopped, or built before live settings existed",
      overridePresent: Boolean(overrideRaw),
    }, { status: 503 });
  }

  const effective = parseJson(effectiveRaw);
  if (!effective) {
    return Response.json({ ok: false, error: "the gateway published settings that will not parse" }, { status: 502 });
  }

  const { settings, readOnly, source } = splitSettings(effective);
  return Response.json({ ok: true, settings, readOnly, source });
}

export async function POST(request) {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected a JSON body" }, { status: 400 });
  }

  if (body.confirm !== "apply") {
    return Response.json({ ok: false, error: 'type "apply" to confirm' }, { status: 400 });
  }

  const settings = body.settings;
  const problem = validateSettings(settings);
  if (problem) {
    return Response.json({ ok: false, error: problem }, { status: 400 });
  }

  const { redis, unavailable } = await connect();
  if (unavailable) return unavailable;

  await redis.set(OVERRIDE_KEY, JSON.stringify(settings));
  console.log(`[admin] ${gate.user.username} changed the enforcement settings`);

  // The gateway validates independently and may still refuse. The page polls
  // the effective key afterwards to find out, so this only reports that the
  // request was stored.
  return Response.json({ ok: true, stored: true });
}

export async function DELETE() {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;

  const { redis, unavailable } = await connect();
  if (unavailable) return unavailable;

  const removed = await redis.del(OVERRIDE_KEY);
  console.log(`[admin] ${gate.user.username} reverted the enforcement settings to the config file`);
  return Response.json({ ok: true, reverted: removed > 0 });
}
