import { BlockList, isIP } from "node:net";

// Ranges that name no one on the public internet. Looking one up would hand an
// internal address to a third-party service and plot it somewhere meaningless.
// The RFC 5737 documentation ranges the demo attacks from are left public.
const NOT_PUBLIC = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.168.0.0", 16],
]) {
  NOT_PUBLIC.addSubnet(network, prefix, "ipv4");
}
for (const [network, prefix] of [["::", 127], ["fc00::", 7], ["fe80::", 10]]) {
  NOT_PUBLIC.addSubnet(network, prefix, "ipv6");
}

// Anything that is not an address at all counts as private too: the question
// this answers is "may it leave the machine", and the safe answer is no.
export function isPrivateIP(ip = "") {
  if (!ip || ip === "localhost") return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return isPrivateIP(mapped[1]);
  const family = isIP(ip);
  if (!family) return true;
  return NOT_PUBLIC.check(ip, family === 4 ? "ipv4" : "ipv6");
}

const cache = globalThis.__iasgGeoCache || new Map();
globalThis.__iasgGeoCache = cache;

function clampRiskScore(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) return 0;
  return Math.min(100, Math.max(0, Math.round(score)));
}

async function fetchJson(url, options = {}, timeoutMs = 1800) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function lookupSelfGeo() {
  if (cache.has("__self__")) return cache.get("__self__");
  const row = await fetchJson("http://ip-api.com/json/?fields=status,query,lat,lon,city,country,org");
  const self =
    row?.status === "success" && row.lat != null && row.lon != null
      ? { lat: row.lat, lon: row.lon, city: row.city || "", country: row.country || "", ip: row.query || "" }
      : null;
  cache.set("__self__", self);
  return self;
}

export async function lookupGeo(ips) {
  const unique = [...new Set(ips.filter((ip) => ip && !isPrivateIP(ip)))];
  const missing = unique.filter((ip) => !cache.has(ip));

  if (missing.length > 0) {
    const rows = await fetchJson(
      "http://ip-api.com/batch?fields=status,query,lat,lon,city,country,org",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(missing.slice(0, 80)),
      },
    );
    for (const row of rows || []) {
      if (row?.query) {
        cache.set(row.query, row.status === "success" ? row : { private: false });
      }
    }
  }

  return Object.fromEntries(unique.map((ip) => [ip, cache.get(ip) || null]));
}

export function summarizeSources(events = []) {
  const byIp = new Map();
  for (const event of events) {
    const ip = event.ip;
    if (!ip) continue;
    const current = byIp.get(ip) || { ip, requests: 0, alerts: 0, lastRisk: 0 };
    current.requests += 1;
    if (event.fired?.length) current.alerts += 1;
    current.lastRisk = Math.max(current.lastRisk, clampRiskScore(event.riskScore));
    byIp.set(ip, current);
  }
  return [...byIp.values()].sort((a, b) => b.requests - a.requests);
}
