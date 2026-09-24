import { getRedis } from "@/lib/redis";
import { require as requireRole } from "@/lib/auth";
import { isPrivateIP, lookupGeo } from "@/lib/geo";
import { parseEventMessage } from "@/lib/telemetry";
import { parseJson, readCampaigns, readPolicyFor } from "@/lib/plane";
import { canonicalSignals } from "@/app/ui/format";

export const dynamic = "force-dynamic";

/**
 * Everything the system knows about one address.
 *
 * Filtering the events table by an address answers "what did it send". The
 * questions that actually decide what to do about it -- is it under policy and
 * for how much longer, did the agent group it with anything, which signals does
 * it keep tripping, how long has it been at this -- were spread across four
 * pages. This gathers them.
 */

// How deep to look for this address's own traffic. The stream holds
// stream_maxlen; scanning all of it for one address is a single range read.
const SCAN_DEPTH = 2000;

export async function GET(request, { params }) {
  const gate = await requireRole("viewer");
  if (gate.denied) return gate.denied;

  const { address } = await params;
  const ip = decodeURIComponent(address || "");
  if (!ip) {
    return Response.json({ error: "no address given" }, { status: 400 });
  }

  try {
    const redis = await getRedis();

    const [entries, campaigns, policy, latestRaw] = await Promise.all([
      redis.xRevRange("iasg:events", "+", "-", { COUNT: SCAN_DEPTH }),
      readCampaigns(redis),
      readPolicyFor(redis, ip),
      redis.get(`iasg:ip:${ip}:latest`).catch(() => null),
    ]);

    const events = (entries || [])
      .map((entry) => {
        const event = parseEventMessage(entry.message);
        return event ? { id: entry.id, ...event } : null;
      })
      .filter((event) => event && event.ip === ip);

    // Signal tallies, and the endpoints this address actually went for. Both
    // say more about intent than a raw request count does.
    const signals = {};
    const paths = {};
    const statuses = {};
    const decisions = {};
    let alerts = 0;

    for (const event of events) {
      // Deduped so a historical event recorded before the traversal/enumeration
      // detector was consolidated to one signal id doesn't tally itself twice.
      for (const name of canonicalSignals(event.fired)) signals[name] = (signals[name] || 0) + 1;
      if (event.fired?.length) alerts += 1;
      if (event.path) paths[event.path] = (paths[event.path] || 0) + 1;
      if (event.status) statuses[event.status] = (statuses[event.status] || 0) + 1;
      if (event.decision) decisions[event.decision] = (decisions[event.decision] || 0) + 1;
    }

    const times = events.map((e) => e.ts).filter(Boolean).sort();
    const priv = isPrivateIP(ip);
    const geo = priv ? {} : await lookupGeo([ip]);
    const loc = geo[ip];

    return Response.json({
      redis: true,
      ip,
      private: priv,
      location: priv
        ? { city: "Private network", country: "RFC1918", lat: null, lon: null }
        : {
            city: loc?.city || "",
            country: loc?.country || "",
            lat: loc?.lat ?? null,
            lon: loc?.lon ?? null,
          },
      policy,
      // Every campaign that named this address, so an operator can see it is
      // part of something larger before acting on it alone.
      campaigns: campaigns.filter((c) => (c.ips || []).includes(ip)),
      events,
      summary: {
        requests: events.length,
        alerts,
        firstSeen: times[0] || null,
        lastSeen: times[times.length - 1] || null,
        signals: Object.entries(signals).sort((a, b) => b[1] - a[1]),
        paths: Object.entries(paths).sort((a, b) => b[1] - a[1]).slice(0, 12),
        statuses: Object.entries(statuses).sort((a, b) => b[1] - a[1]),
        decisions: Object.entries(decisions).sort((a, b) => b[1] - a[1]),
        // The window searched, so "12 requests" is never mistaken for
        // "12 requests ever".
        scanned: entries?.length || 0,
      },
      latest: latestRaw ? parseJson(latestRaw) : null,
    });
  } catch (err) {
    return Response.json(
      { redis: false, error: err.message, ip, events: [], campaigns: [], policy: null },
      { status: 200 },
    );
  }
}
