import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";
import { parseJson, POLICY_PREFIX, scanKeys } from "@/lib/plane";
import { getPool } from "@/lib/postgres";
import { isIP } from "node:net";

export const dynamic = "force-dynamic";

// This removes the validated address-wide key and its bounded endpoint-scoped
// siblings. Unlike an override, it takes effect immediately; the agent can
// write a new policy next cycle if the campaign is still active.
export async function DELETE(_request, { params }) {
  const gate = await requireRole("operator");
  if (gate.denied) return gate.denied;

  const { address } = await params;
  const ip = decodeURIComponent(address || "").trim();
  if (!isAddress(ip)) {
    return Response.json({ ok: false, error: "not an IP address" }, { status: 400 });
  }

  try {
    const redis = await getRedis();
    const keys = await scanKeys(redis, `${POLICY_PREFIX}${ip}:*`);
    keys.push(`${POLICY_PREFIX}${ip}`);
    const values = keys.length ? await redis.mGet(keys) : [];
    const policyIds = values.flatMap((raw) => {
      const id = parseJson(raw)?.policy_id;
      return id ? [id] : [];
    });
    const removed = keys.length ? await redis.del(keys) : 0;
    let auditRecorded = false;
    const pool = getPool();
    if (pool && policyIds.length) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          "UPDATE policy_recommendations SET status='revoked',updated_at=now() WHERE policy_id=ANY($1::text[])",
          [policyIds],
        );
        for (const policyId of policyIds) {
          await client.query(
            "INSERT INTO policy_audit (policy_id,event,actor,details) VALUES ($1,'revoked',$2,$3::jsonb)",
            [policyId, gate.user.username, JSON.stringify({ target_identity: ip })],
          );
        }
        await client.query("COMMIT");
        auditRecorded = true;
      } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        console.error(`[policy] could not audit revocation for ${ip}: ${err.message}`);
      } finally {
        client.release();
      }
    }
    console.log(`[policy] ${gate.user.username} removed policy for ${ip}: ${removed ? "deleted" : "absent"}`);
    return Response.json({ ok: true, ip, removed: removed > 0, auditRecorded });
  } catch (err) {
    return Response.json({ ok: false, error: err.message }, { status: 503 });
  }
}

function isAddress(value) {
  return isIP(value) !== 0;
}
