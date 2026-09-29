/**
 * Deployment mistakes that fail silently, read off the event stream.
 *
 * Both of these leave the gateway running, recording and looking healthy while
 * it protects nothing, and neither produces an error anywhere:
 *
 *   private-sources   trusted_proxies does not name the proxy in front of the
 *                     gateway, so every request is attributed to that proxy.
 *                     Private addresses are exempt from blocking in both the
 *                     gateway and the decision engine, so nothing is ever
 *                     blocked.
 *   missing-routes    the route table does not describe the API, so ordinary
 *                     requests record as <unmatched> and ordinary clients
 *                     start to look like scanners.
 *
 * These are heuristics over a recent window, so each one names what it saw and
 * says when it is expected, rather than asserting a misconfiguration.
 */

import { isPrivateIP } from "./geo.js";

export const UNMATCHED = "<unmatched>";

// Below this many requests a share is noise: a few curl calls from a laptop
// are not a deployment.
export const MIN_EVENTS = 30;
export const PRIVATE_SHARE = 0.9;

// A missing route is one several clients keep calling. Scanners do the
// opposite -- many paths, each requested once -- so repetition across clients
// is what separates an unlisted endpoint from reconnaissance.
export const MIN_ROUTE_CLIENTS = 2;
export const MIN_ROUTE_REQUESTS = 5;
export const MAX_ROUTES_LISTED = 5;

// Detectors that fire on the path itself. A request they flagged is an attack
// on a path, not evidence that the path belongs in the route table.
const PATH_ATTACK_SIGNALS = new Set([
  "enumeration_path_traversal",
  "path_traversal",
  "enumeration",
  "sql_injection",
]);

// Segments that vary per resource. Grouping on them turns /users/1, /users/2
// and /users/3 -- one request each -- into the one endpoint they are.
const VARIABLE_SEGMENT = [
  /^\d+$/,
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  /^[0-9a-f]{16,}$/i,
  // Long opaque tokens, but only with a digit: password-reset-confirmation is
  // a word, not an id.
  /^(?=.*\d)[0-9A-Za-z_-]{20,}$/,
];

export function suggestTemplate(path = "") {
  return path
    .split("/")
    .map((segment) => (VARIABLE_SEGMENT.some((re) => re.test(segment)) ? "{id}" : segment))
    .join("/");
}

function privateSources(events) {
  if (events.length < MIN_EVENTS) return null;

  const counts = new Map();
  let privateRequests = 0;
  for (const event of events) {
    if (!isPrivateIP(event.ip)) continue;
    privateRequests += 1;
    counts.set(event.ip, (counts.get(event.ip) || 0) + 1);
  }

  const share = privateRequests / events.length;
  if (share < PRIVATE_SHARE) return null;

  const addresses = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([ip, requests]) => ({ ip, requests }));

  return {
    id: "private-sources",
    title: "Most traffic comes from private addresses, which are never blocked",
    detail:
      `${Math.round(share * 100)}% of the last ${events.length} requests came from private addresses, ` +
      "which the gateway and decision engine never block. If clients reach the gateway through a proxy " +
      "or load balancer, add its address to server.trusted_proxies in the gateway config and restart " +
      "the gateway. Expected if your clients really are on a private network, or you are testing from " +
      "this machine.",
    items: addresses.map((row) => ({
      label: row.ip,
      value: `${row.requests} ${row.requests === 1 ? "request" : "requests"}`,
    })),
  };
}

function missingRoutes(events) {
  const groups = new Map();
  for (const event of events) {
    if (event.routeTemplate !== UNMATCHED) continue;
    if ((event.fired || []).some((name) => PATH_ATTACK_SIGNALS.has(name))) continue;

    const key = `${event.method || "GET"} ${suggestTemplate(event.path)}`;
    const group = groups.get(key) || { key, requests: 0, clients: new Set() };
    group.requests += 1;
    group.clients.add(event.ip);
    groups.set(key, group);
  }

  const routes = [...groups.values()]
    .filter(
      (g) =>
        g.clients.size >= MIN_ROUTE_CLIENTS &&
        g.requests >= MIN_ROUTE_REQUESTS &&
        // Repeated use, not one visit per client.
        g.requests >= 2 * g.clients.size,
    )
    .sort((a, b) => b.requests - a.requests);

  if (!routes.length) return null;

  const total = routes.reduce((sum, g) => sum + g.requests, 0);
  return {
    id: "missing-routes",
    title: `${routes.length} ${routes.length === 1 ? "endpoint is" : "endpoints are"} missing from the route table`,
    detail:
      `${total} recent requests from several clients matched no route template. Unmatched paths count ` +
      "toward unknown-route scanning, so regular clients of these endpoints can be flagged as scanners. " +
      "Add them to routes.templates in the gateway config and restart the gateway; {id} marks a segment " +
      "that varies.",
    items: routes.slice(0, MAX_ROUTES_LISTED).map((g) => ({
      label: g.key,
      value: `${g.requests} requests · ${g.clients.size} clients`,
    })),
  };
}

export function setupChecks(events = []) {
  return [privateSources(events), missingRoutes(events)].filter(Boolean);
}
