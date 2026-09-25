import { Pool } from "pg";

const globalForPg = globalThis;

/**
 * The durable store, or null when there isn't one.
 *
 * Optional on purpose, exactly as it is for the control plane: without
 * IASG_POSTGRES_URL the console simply has no history to show, and every
 * live panel keeps working from Redis.
 */
export function getPool() {
  const url = process.env.IASG_POSTGRES_URL || process.env.DATABASE_URL;
  if (!url) return null;

  if (!globalForPg.__iasgPool) {
    const pool = new Pool({
      connectionString: url,
      max: 4,
      connectionTimeoutMillis: 2000,
      idleTimeoutMillis: 30_000,
    });
    // An idle client erroring out must not take the process with it.
    pool.on("error", (err) => console.error("postgres:", err.message));
    globalForPg.__iasgPool = pool;
  }

  return globalForPg.__iasgPool;
}

/**
 * Empty tables together or not at all, and say how many rows each held.
 *
 * `failure` is merged into every failed result, so a caller that reports
 * `cleared` can keep it present when nothing was cleared.
 */
export async function truncateTables(tables, failure = {}) {
  const pool = getPool();
  if (!pool) return { ok: false, reason: "no durable store (IASG_POSTGRES_URL unset)", ...failure };

  const client = await pool.connect();
  try {
    const before = {};
    for (const table of tables) {
      const { rows } = await client.query(`SELECT count(*)::int AS n FROM ${table}`);
      before[table] = rows[0].n;
    }
    // One transaction: a half-cleared record is worse than either state.
    await client.query("BEGIN");
    await client.query(`TRUNCATE ${tables.join(", ")}`);
    // Non-fatal: the sequence only exists once the control plane has run, and a
    // clear before it ever has is still a valid clear.
    await client.query("SELECT setval('campaign_id_seq', 1, false)").catch(() => {});
    await client.query("COMMIT");
    return { ok: true, cleared: before };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    return { ok: false, reason: err.message, ...failure };
  } finally {
    client.release();
  }
}
