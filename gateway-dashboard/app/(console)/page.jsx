"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { useMemo, useState } from "react";
import { PageHead } from "@/app/ui/chrome";
import { EVENT_COLUMNS, exportCsv } from "@/app/ui/export";
import { clampRiskScore, requestHistogram, riskTone, signalMeta } from "@/app/ui/format";
import { Loading, Metric, SegmentedControl } from "@/app/ui/parts";
import { SetupWarnings } from "@/app/ui/setup-warnings";
import { useLive } from "@/app/ui/store";

const TrafficMap = dynamic(() => import("@/app/traffic-map"), {
  ssr: false,
  loading: () => (
    <div className="map-canvas map-loading">
      <Loading label="Loading map…" />
    </div>
  ),
});

const RANGE_COPY = {
  "1h": "the last hour",
  "24h": "the last 24 hours",
  "7d": "the last 7 days",
};
const RANGES = Object.keys(RANGE_COPY).map((value) => ({ value, label: value }));

export default function OverviewPage() {
  const { overview, stats, events, sources, attackers, policies, campaigns, busy, instruct, setup } =
    useLive();
  const [range, setRange] = useState("24h");

  const histogram = useMemo(() => requestHistogram(events), [events]);
  const histMax = Math.max(1, ...histogram);
  const alertRate = stats.requests
    ? ((stats.alerts / stats.requests) * 100).toFixed(1)
    : "0.0";
  const active = campaigns.filter((c) => c.status === "active").length;
  const policyBlocked = policies.filter(
    (p) => p.action === "temp_block" || p.action === "temporary_block",
  ).length;
  const policyThrottled = policies.filter(
    (p) => p.action === "throttle" || p.action === "rate_limited",
  ).length;

  const signalRows = useMemo(() => {
    const entries = Object.entries(stats.signals || {});
    const total = entries.reduce((sum, [, count]) => sum + count, 0) || 1;
    return entries
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => ({
        name,
        count,
        pct: Math.round((count / total) * 100),
        ...signalMeta(name),
      }));
  }, [stats.signals]);
  const signalHits = signalRows.reduce((sum, row) => sum + row.count, 0);

  // The zset only carries an alert count per IP -- place and risk aren't
  // stored there, so both are recovered from the visible event window,
  // same as everywhere else this console falls back to what it can see.
  const attackerRows = useMemo(() => {
    return attackers.map((row) => {
      const source = sources.find((s) => s.ip === row.ip);
      const ipEvents = events.filter((e) => e.ip === row.ip);
      const risk = ipEvents.length
        ? Math.max(...ipEvents.map((e) => clampRiskScore(e.riskScore)))
        : null;
      const place = source
        ? source.private
          ? "Private network"
          : [source.city, source.country].filter(Boolean).join(", ") || "Unknown location"
        : "";
      const meta = place
        ? `${place} · ${row.alerts.toLocaleString()} ${row.alerts === 1 ? "alert" : "alerts"}`
        : "";
      return { ip: row.ip, alerts: row.alerts, meta, risk };
    });
  }, [attackers, sources, events]);

  const privateCount = sources.filter((s) => s.private).length;
  const topRegion = useMemo(() => {
    const totals = {};
    for (const s of sources) {
      if (s.private || !s.country) continue;
      totals[s.country] = (totals[s.country] || 0) + s.requests;
    }
    const entries = Object.entries(totals).sort((a, b) => b[1] - a[1]);
    if (!entries.length) return null;
    const grand = entries.reduce((sum, [, n]) => sum + n, 0) || 1;
    return { name: entries[0][0], pct: ((entries[0][1] / grand) * 100).toFixed(1) };
  }, [sources]);

  return (
    <>
      <PageHead
        eyebrow="Gateway telemetry"
        title="Overview"
        actions={
          <>
            <SegmentedControl value={range} onChange={setRange} options={RANGES} />
            <button
              type="button"
              className="act"
              disabled={!events.length}
              onClick={() => exportCsv("overview", events, EVENT_COLUMNS)}
              title={events.length ? `Download these ${events.length} events as CSV` : "Nothing to export"}
            >
              Export
            </button>
          </>
        }
      >
        Traffic, detection and enforcement across all upstreams for {RANGE_COPY[range]}.
      </PageHead>

      <SetupWarnings checks={setup} />

      <section className="metrics">
        <Metric
          label="Total requests"
          value={stats.requests}
          detail={stats.derived ? "visible window" : "since gateway start"}
          bars={histogram}
          max={histMax}
          href="/events"
        />
        <Metric
          label="Alerts"
          value={stats.alerts}
          tone={stats.alerts > 0 ? "high" : undefined}
          badge={stats.alerts > 0 ? `${alertRate}% of traffic` : null}
          detail={`${active} active ${active === 1 ? "campaign" : "campaigns"}`}
          href="/events?alerts=1"
        />
        <Metric
          label="Under policy action"
          value={policies.length}
          detail={
            <>
              <b style={{ color: "var(--bad)" }}>{policyBlocked}</b> blocked{" "}
              <b style={{ color: "var(--warn)" }}>{policyThrottled}</b> throttled
            </>
          }
          href="/policy"
        />
        <Metric
          label="Unique source IPs"
          value={sources.length}
          detail={`${sources.filter((s) => s.private).length} private`}
          href="/events"
        />
      </section>

      <article className="card map-card panel-primary">
        <div className="card-head map-head">
          <div>
            <h2>Request origins</h2>
            <span>
              {sources.length.toLocaleString()} sources · {attackerRows.length} currently
              alerting
            </span>
          </div>
          <div className="map-legend">
            <span>
              <i style={{ background: "var(--map-public)" }} />
              Public traffic {sources.filter((s) => !s.private && s.lat != null).length}
            </span>
            <span>
              <i style={{ background: "var(--map-site)" }} />
              Gateway site
            </span>
            <span>
              <i className="alert" style={{ background: "var(--map-alert)" }} />
              Alerting source {attackerRows.length}
            </span>
            <span>
              <i style={{ background: "var(--map-private)" }} />
              Private IP {privateCount}
            </span>
          </div>
        </div>
        <TrafficMap sources={sources} site={overview.site} />
        <div className="map-foot">
          {topRegion ? (
            <span>
              Top region <strong>{topRegion.name} — {topRegion.pct}%</strong>
            </span>
          ) : null}
          <span>
            Private-range traffic <strong>{privateCount} {privateCount === 1 ? "address" : "addresses"}</strong>
          </span>
          <Link href="/events">Inspect raw events →</Link>
        </div>
      </article>

      <section className="overview-secondary">
        <article className="card">
          <div className="card-head">
            <h2>Detected signal types</h2>
            <span>{signalHits.toLocaleString()} signal hits · {range}</span>
          </div>
          {signalRows.length === 0 ? (
            <p className="empty">No hits in the current window.</p>
          ) : (
            <ul className="signal-bars">
              {signalRows.map((row) => (
                <li key={row.name}>
                  <div className="signal-bar-top">
                    <span className="swatch" style={{ background: row.color }} />
                    <Link href={`/events?signal=${encodeURIComponent(row.name)}`}>{row.label}</Link>
                    <b>
                      {row.count.toLocaleString()} · <span>{row.pct}%</span>
                    </b>
                  </div>
                  <div className="signal-bar-track">
                    <span style={{ width: `${row.pct}%`, background: row.color }} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </article>

        <article className="card">
          <div className="card-head">
            <h2>Top offending IPs</h2>
            <span>Ranked by alert volume</span>
          </div>
          {attackerRows.length === 0 ? (
            <p className="empty">No alerting IPs yet.</p>
          ) : (
            <div className="ip-grid">
              {attackerRows.map((row) => (
                <div className="ip-row" key={row.ip}>
                  <Link href={`/events?ip=${encodeURIComponent(row.ip)}`} className="mono ip-row-addr">
                    {row.ip}
                    {row.meta ? <span className="meta">{row.meta}</span> : null}
                  </Link>
                  <div className="ip-row-risk">
                    <strong className={row.risk == null ? "" : riskTone(row.risk)}>
                      {row.risk == null ? "—" : row.risk}
                    </strong>
                    <small>risk</small>
                  </div>
                  <button
                    type="button"
                    className="act small ip-block-btn"
                    disabled={Boolean(busy)}
                    onClick={() => instruct([row.ip], "temp_block", `ip-${row.ip}`)}
                    title={`Instruct temp block for ${row.ip}`}
                  >
                    {busy === `ip-${row.ip}:temp_block` ? "…" : "Block IP"}
                  </button>
                </div>
              ))}
            </div>
          )}
        </article>
      </section>
    </>
  );
}
