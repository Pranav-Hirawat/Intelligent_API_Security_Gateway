import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";
import { isIP } from "node:net";

export const dynamic = "force-dynamic";

const OVERRIDE_STREAM = process.env.IASG_OVERRIDE_STREAM || "iasg_overrides";

// Exactly the ladder the decision engine knows. Anything else is rejected here
// rather than written and silently ignored a cycle later.
const ACTIONS = new Set(["monitor", "throttle", "temp_block", "escalate"]);

// Deliberately not an enforcement path. This writes an instruction to the
// stream the decision engine reads; the agent still runs it through the
// allowlist and the collateral checks before any policy is written. A typo
// here cannot block an address the operator declared as theirs.
export async function POST(request) {
  // Changing enforcement is an operator's job. Checked here rather than in the
  // UI, because a hidden button is presentation and this is authorisation.
  const gate = await requireRole("operator");
  if (gate.denied) return gate.denied;

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected JSON" }, { status: 400 });
  }

  const ip = String(body.ip || "").trim();
  const action = String(body.action || "").trim();
  // Who did it comes from the session, never from the request body: an actor
  // the caller can choose is not an audit trail.
  const actor = gate.user.username;
  const reason = String(body.reason || "").trim().slice(0, 280);

  if (!ip) {
    return Response.json({ ok: false, error: "ip is required" }, { status: 400 });
  }
  if (!ACTIONS.has(action)) {
    return Response.json(
      { ok: false, error: `action must be one of ${[...ACTIONS].join(", ")}` },
      { status: 400 },
    );
  }
  if (!isAddress(ip)) {
    return Response.json({ ok: false, error: "not an IP address" }, { status: 400 });
  }

  try {
    const redis = await getRedis();
    const id = await redis.xAdd(OVERRIDE_STREAM, "*", {
      ip,
      action,
      actor,
      reason: reason || `set from the dashboard`,
    });

    // Honest about latency: the agent picks this up on its next cycle, so the
    // UI must not imply the address is already blocked.
    return Response.json({ ok: true, id, ip, action, applied: "next cycle" });
  } catch (err) {
    return Response.json({ ok: false, error: err.message }, { status: 503 });
  }
}

function isAddress(value) {
  return isIP(value) !== 0;
}
