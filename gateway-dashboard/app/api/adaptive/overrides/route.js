import crypto from "node:crypto";
import { isIP } from "node:net";
import { require as requireRole } from "@/lib/auth";
import { getPool } from "@/lib/postgres";
import { getRedis } from "@/lib/redis";

export const dynamic = "force-dynamic";
const OVERRIDE_STREAM = process.env.IASG_OVERRIDE_STREAM || "iasg_overrides";

export async function POST(request) {
  const gate = await requireRole("operator");
  if (gate.denied) return gate.denied;
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected JSON" }, { status: 400 });
  }
  const target = String(body.target_identity || "").trim();
  const action = String(body.action || "");
  const duration = Number(body.duration_seconds || 900);
  if (!isAddress(target)) return Response.json({ ok: false, error: "valid target_identity is required" }, { status: 400 });
  if (!['allow', 'temp_block'].includes(action)) return Response.json({ ok: false, error: "emergency action must be allow or temp_block" }, { status: 400 });
  const pool = getPool();
  if (!pool) return Response.json({ ok: false, error: "durable adaptive settings are unavailable" }, { status: 503 });
  let config;
  try {
    const settings = await pool.query("SELECT config FROM adaptive_settings WHERE singleton_id=1");
    config = settings.rows[0]?.config;
  } catch (err) {
    return Response.json({ ok: false, error: err.message }, { status: 503 });
  }
  const maximum = Number(config?.guardrails?.maximum_policy_duration_seconds || 0);
  if (!Number.isInteger(duration) || duration < 30 || duration > maximum) {
    return Response.json({ ok: false, error: `duration_seconds must be 30..${maximum}` }, { status: 400 });
  }
  const policyId = crypto.randomUUID();
  const reason = String(body.reason || "emergency analyst override").slice(0, 500);
  try {
    await pool.query(
      "INSERT INTO policy_audit (policy_id,event,actor,details) VALUES ($1,'emergency_requested',$2,$3::jsonb)",
      [policyId, gate.user.username, JSON.stringify({ target, action, duration, reason })],
    );
    const redis = await getRedis();
    await redis.xAdd(OVERRIDE_STREAM, "*", {
      policy_id: policyId,
      ip: target,
      action,
      actor: gate.user.username,
      reason,
      ttl_seconds: String(duration),
      method: "",
      route_template: "",
      emergency: "true",
    });
    return Response.json({ ok: true, policyId, applied: "next decision-engine cycle" });
  } catch (err) {
    await pool.query(
      "INSERT INTO policy_audit (policy_id,event,actor,details) VALUES ($1,'emergency_failed',$2,$3::jsonb)",
      [policyId, gate.user.username, JSON.stringify({ error: err.message })],
    ).catch(() => {});
    return Response.json({ ok: false, error: err.message }, { status: 503 });
  }
}

function isAddress(value) {
  return isIP(value) !== 0;
}
