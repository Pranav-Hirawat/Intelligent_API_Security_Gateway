import { require as requireRole } from "@/lib/auth";
import { validateAdaptive } from "@/lib/adaptive";
import { getPool } from "@/lib/postgres";

export const dynamic = "force-dynamic";

export async function PUT(request) {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;
  const pool = getPool();
  if (!pool) return Response.json({ ok: false, error: "durable store unavailable" }, { status: 503 });

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected JSON" }, { status: 400 });
  }
  if (body.confirm !== "apply") {
    return Response.json({ ok: false, error: 'type "apply" to confirm' }, { status: 400 });
  }
  const config = body.config;
  const problem = validateAdaptive(config);
  if (problem) return Response.json({ ok: false, error: problem }, { status: 400 });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const current = await client.query(
      "SELECT version FROM adaptive_settings WHERE singleton_id=1 FOR UPDATE",
    );
    if (!current.rowCount) throw new ApiError(409, "run the decision engine migration first");
    if (Number(config.version) !== Number(current.rows[0].version)) {
      throw new ApiError(409, "settings changed since this page loaded; reload before saving");
    }
    config.version = Number(current.rows[0].version) + 1;
    await client.query(
      `UPDATE adaptive_settings
          SET version=$1, mode=$2, config=$3::jsonb, source='console', updated_at=now(), updated_by=$4
        WHERE singleton_id=1`,
      [config.version, config.mode, JSON.stringify(config), gate.user.username],
    );
    await client.query(
      "INSERT INTO policy_audit (policy_id,event,actor,details) VALUES ($1,'settings_updated',$2,$3::jsonb)",
      [`settings-v${config.version}`, gate.user.username, JSON.stringify({ mode: config.mode, version: config.version })],
    );
    await client.query("COMMIT");
    return Response.json({ ok: true, config });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    return Response.json({ ok: false, error: err.message }, { status: err.status || 503 });
  } finally {
    client.release();
  }
}

export async function DELETE() {
  const gate = await requireRole("admin");
  if (gate.denied) return gate.denied;
  const pool = getPool();
  if (!pool) return Response.json({ ok: false, error: "durable store unavailable" }, { status: 503 });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const current = await client.query(
      "SELECT version, file_config FROM adaptive_settings WHERE singleton_id=1 FOR UPDATE",
    );
    if (!current.rowCount) throw new ApiError(409, "run the decision engine migration first");
    const fileConfig = current.rows[0].file_config;
    const problem = validateAdaptive(fileConfig);
    if (problem) throw new ApiError(409, `the config-file adaptive settings are invalid: ${problem}`);

    fileConfig.version = Number(current.rows[0].version) + 1;
    await client.query(
      `UPDATE adaptive_settings
          SET version=$1, mode=$2, config=$3::jsonb, source='file', updated_at=now(), updated_by=$4
        WHERE singleton_id=1`,
      [fileConfig.version, fileConfig.mode, JSON.stringify(fileConfig), gate.user.username],
    );
    await client.query(
      "INSERT INTO policy_audit (policy_id,event,actor,details) VALUES ($1,'settings_reverted',$2,$3::jsonb)",
      [`settings-v${fileConfig.version}`, gate.user.username, JSON.stringify({ mode: fileConfig.mode, version: fileConfig.version })],
    );
    await client.query("COMMIT");
    return Response.json({ ok: true, config: fileConfig });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    return Response.json({ ok: false, error: err.message }, { status: err.status || 503 });
  } finally {
    client.release();
  }
}

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
