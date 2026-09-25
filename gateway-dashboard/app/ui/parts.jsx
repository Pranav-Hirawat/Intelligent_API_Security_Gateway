"use client";

import Link from "next/link";
import { useState } from "react";
import { exportCsv, exportJson, snapshotPng } from "./export";
import { EmptyIcon, SpinnerIcon } from "./icons";
import { useLive } from "./store";
import {
  ACTION_TONE,
  DISPLAY_TIME_ZONE_LABEL,
  LADDER,
  actionLabel,
  canonicalSignals,
  clampRiskScore,
  formatTime,
  isValidIp,
  riskTone,
  signalMeta,
} from "./format";

/**
 * A trend line, not a bar chart. The bucketed request histogram used to
 * render as fixed-width vertical bars (`.spark span`) -- fine for evenly
 * busy data, but the real histogram is mostly-zero buckets with one or two
 * spikes, which rendered as a row of near-invisible slivers next to one
 * solid block. A polyline reads the same shape as a trend regardless of how
 * lopsided the underlying counts are.
 */
function Sparkline({ values, max, width = 96, height = 34 }) {
  const top = Math.max(1, max ?? Math.max(...values, 1));
  const last = values.length - 1;
  const points = values.map((v, i) => {
    const x = last > 0 ? (i / last) * width : width;
    const y = height - 3 - (Math.max(0, v) / top) * (height - 6);
    return [x, y];
  });
  const [ex, ey] = points[points.length - 1] || [width, height];
  return (
    <svg className="spark-svg" width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
      <polyline
        points={points.map(([x, y]) => `${x},${y}`).join(" ")}
        fill="none"
        stroke="var(--accent)"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx={ex} cy={ey} r="2.4" fill="var(--accent)" />
    </svg>
  );
}

export function Metric({ label, value, detail, bars, max, href, badge, tone }) {
  const text = (
    <>
      <p>{label}</p>
      {badge ? (
        <span className="metric-value-row">
          <strong className={tone || ""}>{Number(value || 0).toLocaleString()}</strong>
          <span className={`metric-badge ${tone || ""}`}>{badge}</span>
        </span>
      ) : (
        <strong className={tone || ""}>{Number(value || 0).toLocaleString()}</strong>
      )}
      <small>{detail}</small>
    </>
  );

  // The one tile with a trend line sits its number on the left and the
  // line on the right, bottom-aligned -- every other tile just stacks.
  const body = bars ? (
    <div className="metric-with-spark">
      <div>{text}</div>
      <Sparkline values={bars} max={max} />
    </div>
  ) : (
    text
  );

  // A metric that has a page behind it should take you there.
  return href ? (
    <Link href={href} className="metric linked">
      {body}
    </Link>
  ) : (
    <article className="metric">{body}</article>
  );
}

export function ActionRow({ ips, current, busyKey, busy, onInstruct, label = "Overrule the agent" }) {
  return (
    <div className="campaign-actions">
      <span>{label}</span>
      {LADDER.map((action) => (
        <button
          key={action}
          type="button"
          disabled={Boolean(busy) || action === current}
          className={action === current ? "act current" : "act"}
          onClick={() => onInstruct(ips, action, busyKey)}
          title={
            action === current
              ? `The agent already chose ${actionLabel(action)}`
              : `Instruct ${actionLabel(action)} for ${ips.length} ${
                  ips.length === 1 ? "address" : "addresses"
                }`
          }
        >
          {busy === `${busyKey}:${action}` ? "…" : actionLabel(action)}
        </button>
      ))}
    </div>
  );
}

/**
 * The same five fields for every policy type -- a recommendation on Adaptive,
 * an active policy here or on an IP's own page. Everything but `explanation`
 * is optional: a caller that already has clean top-level fields (Policy, IP
 * detail -- see lib/plane.js's readPolicies) passes them directly; a caller
 * that only has the raw explanation blob (Adaptive's recommendation rows,
 * sourced from Postgres) falls back to reading it out of `explanation.final`,
 * which carries the same data because both are built
 * from one PolicyDecision.
 *
 * Risk score and policy confidence are intentionally separate: severity and
 * certainty answer different questions for a security decision.
 */
export function DecisionExplanation({
  explanation = {},
  riskScore,
  confidence,
}) {
  const baseline = explanation.baseline || {};
  const final = explanation.final || {};
  const risk = riskScore ?? final.risk_score;
  const conf = confidence ?? final.confidence;

  return (
    <details className="decision-explanation">
      <summary>Inspect scoring</summary>
      <p>
        Risk score {risk ?? "—"}/100. Policy confidence {conf ?? "—"}.
      </p>
      {baseline.threshold != null || baseline.observed != null ? (
        <p>
          Baseline {baseline.baseline_ready ? "ready" : "not ready"}: observed{" "}
          {baseline.observed ?? "—"}, threshold {baseline.threshold ?? "—"}, deviation{" "}
          {baseline.deviation ?? "—"}.
        </p>
      ) : null}
      {(final.guardrails || []).length ? <p>{final.guardrails.join("; ")}</p> : null}
    </details>
  );
}

export function CampaignCard({
  campaign: c,
  onInstruct,
  busy,
  compact,
  // Selection is optional: the IP page renders these bare in a list and
  // never passes them, so it looks exactly as it did before. Only the
  // Campaigns grid, where each card can be checked for a bulk action, sets
  // these -- which is also what puts the "selected" class in play, since
  // .campaign-grid > .campaign.selected is the only place that class means
  // anything visually.
  selectable,
  selected,
  onToggleSelect,
}) {
  const classes = [c.status === "contained" ? "campaign contained" : "campaign"];
  if (selected) classes.push("selected");

  return (
    <li className={classes.join(" ")}>
      {selectable ? (
        <label className="select-row">
          <input type="checkbox" checked={Boolean(selected)} onChange={onToggleSelect} />
          select for bulk action
        </label>
      ) : null}

      <div className="campaign-head">
        <strong>
          #{c.id} {c.type}
        </strong>
        <span className={`risk ${ACTION_TONE[c.lastAction] || "low"}`}>
          {actionLabel(c.lastAction)}
        </span>
      </div>

      <div className="campaign-facts">
        <span>
          {c.ips.length} {c.ips.length === 1 ? "IP" : "IPs"}
        </span>
        <span>confidence {c.confidence.toFixed(2)}</span>
        <span>{c.severity}</span>
        <span>{c.events} events</span>
        <span className={c.status === "contained" ? "tag good" : "tag"}>{c.status}</span>
        {/* The stored narration and the card clock both carry explicit IST,
            so alerts and the browser describe the same operational timeline. */}
        {c.lastSeen ? (
          <span title={`First seen ${formatTime(c.firstSeen)} ${DISPLAY_TIME_ZONE_LABEL}, last seen ${formatTime(c.lastSeen)} ${DISPLAY_TIME_ZONE_LABEL}`}>
            {c.firstSeen && formatTime(c.firstSeen) !== formatTime(c.lastSeen)
              ? `${formatTime(c.firstSeen)}–${formatTime(c.lastSeen)}`
              : formatTime(c.lastSeen)}
          </span>
        ) : null}
      </div>

      <p className="campaign-reason">{c.reason}</p>

      {!compact ? (
        <>
          {c.stages.length > 1 ? (
            <p className="campaign-note">
              <b>Stages</b> {c.stages.join(" → ")} — {c.stages.length} phases of one
              intrusion, not {c.stages.length} separate attacks
            </p>
          ) : null}

          {c.rotations > 0 ? (
            <p className="campaign-note">
              <b>Continuity</b> re-identified by behaviour through {c.rotations} address{" "}
              {c.rotations === 1 ? "change" : "changes"}
            </p>
          ) : null}

          {c.persistence > 0 ? (
            <p className="campaign-note">
              <b>Adapted</b> survived {c.persistence} enforcement{" "}
              {c.persistence === 1 ? "round" : "rounds"} — answered with{" "}
              {actionLabel(c.lastAction)}
            </p>
          ) : null}

          {c.outcome ? (
            <p className="campaign-note">
              <b>Outcome</b> {c.outcome}
            </p>
          ) : null}

          {c.explanation ? <p className="campaign-explain">{c.explanation}</p> : null}

          {c.assessment ? (
            // Unlike the explanation above, this field has no offline
            // template -- it exists only when the language provider answered.
            <p className="campaign-note assess">
              <b>Ollama assessment</b> {c.assessment}
            </p>
          ) : null}
        </>
      ) : null}

      <div className="campaign-ips">
        {c.ips.slice(0, 8).map((ip) => (
          // Every address is a way into everything known about it.
          <Link key={ip} href={`/ip/${encodeURIComponent(ip)}`} className="ip-chip">
            {ip}
          </Link>
        ))}
        {c.ips.length > 8 ? <small>+{c.ips.length - 8} more</small> : null}
      </div>

      {onInstruct ? (
        <ActionRow
          ips={c.ips}
          current={c.lastAction}
          busyKey={`campaign-${c.id}`}
          busy={busy}
          onInstruct={onInstruct}
        />
      ) : null}
    </li>
  );
}

/**
 * One control, not three. .segmented (Campaigns' status filter) and .seg
 * (Events' window/range) were the same idea built twice with slightly
 * different markup; a third call site toggled plain buttons by hand. Callers
 * normalize their own data into { value, label, count?, title? } rather than
 * this component guessing at shapes -- keeps this simple and keeps each
 * page's own data (a plain array of numbers, an array of {label, ms}
 * objects, whatever) from needing to change shape just to be displayed.
 */
export function SegmentedControl({ options, value, onChange }) {
  return (
    <span className="segmented">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className={option.value === value ? "on" : ""}
          onClick={() => onChange(option.value)}
          title={option.title}
        >
          {option.label}
          {option.count != null ? <em>{option.count}</em> : null}
        </button>
      ))}
    </span>
  );
}

/**
 * One exact-IP filter, shared by Events (server-side, paged) and Campaigns/
 * Policy (client-side, over whatever useLive() already has in memory) --
 * same input, same "invalid" state, same Clear affordance, so filtering
 * behaves identically wherever it appears. The caller owns the value (so it
 * can sync it to a URL query param, as Events does) and decides what
 * "matches" means for its own rows; this only validates shape and renders.
 */
export function IpFilterField({ value, onChange, placeholder = "Filter by IP…" }) {
  const invalid = value && !isValidIp(value);
  return (
    <div className={invalid ? "ip-filter invalid" : "ip-filter"}>
      <input
        type="text"
        inputMode="text"
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-invalid={invalid || undefined}
        aria-label="Filter by IP address"
      />
      {value ? (
        <button
          type="button"
          className="ip-filter-clear"
          onClick={() => onChange("")}
          title="Clear filter"
          aria-label="Clear IP filter"
        >
          ×
        </button>
      ) : null}
      {invalid ? <small className="ip-filter-error">Not a valid IP address</small> : null}
    </div>
  );
}

/**
 * One labelled-field family, not two. Settings had Num/Text/Toggle/List;
 * Adaptive had its own local Field handling text/number/select/multiline by
 * itself -- same CSS classes (.field, .field-label), built by hand twice.
 * Field.Textarea (a raw string) and Field.List (a newline-separated array)
 * stay distinct rather than merged: they return different value shapes to
 * their caller, and collapsing them would force one side to convert.
 */
export function Field({ label, hint, children }) {
  return (
    <label className="field block">
      <span className="field-label">{label}</span>
      {children}
      {hint ? <small>{hint}</small> : null}
    </label>
  );
}

Field.Text = function FieldText({ label, value, onChange, hint }) {
  return (
    <Field label={label} hint={hint}>
      <input type="text" value={value ?? ""} onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
};

Field.Number = function FieldNumber({ label, value, onChange, min, max, step, hint }) {
  return (
    <Field label={label} hint={hint}>
      <input
        type="number"
        value={value ?? ""}
        min={min}
        max={max}
        step={step}
        onChange={(e) => onChange(e.target.value === "" ? "" : Number(e.target.value))}
      />
    </Field>
  );
};

Field.Select = function FieldSelect({ label, value, onChange, options, optionLabel, hint }) {
  return (
    <Field label={label} hint={hint}>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((option) => (
          <option key={option} value={option}>
            {optionLabel ? optionLabel(option) : option}
          </option>
        ))}
      </select>
    </Field>
  );
};

// A raw string in a textarea -- Adaptive's prior "multiline" mode. Parsing it
// into ranges/patterns happens outside this component, same as before.
Field.Textarea = function FieldTextarea({ label, value, onChange, hint, rows = 3 }) {
  return (
    <Field label={label} hint={hint}>
      <textarea rows={rows} value={value ?? ""} onChange={(e) => onChange(e.target.value)} />
    </Field>
  );
};

// An array, one entry per line -- Settings' prior "List" mode: patterns and
// CIDRs pasted in from somewhere else, where a textarea takes the paste whole.
Field.List = function FieldList({ label, value, onChange, hint }) {
  return (
    <Field label={label} hint={hint}>
      <textarea
        rows={Math.min(Math.max(value.length + 1, 3), 10)}
        value={value.join("\n")}
        onChange={(e) =>
          onChange(
            e.target.value
              .split("\n")
              .map((line) => line.trim())
              .filter(Boolean),
          )
        }
      />
    </Field>
  );
};

Field.Toggle = function FieldToggle({ label, checked, onChange }) {
  return (
    <label className="check">
      <button
        type="button"
        role="switch"
        aria-checked={Boolean(checked)}
        className={checked ? "switch on" : "switch"}
        onClick={() => onChange(!checked)}
      >
        <span className="knob" />
      </button>
      {label}
    </label>
  );
};

/**
 * Standardizes content, not just the container: every empty state before this
 * used the same .empty visual mechanism but wildly different content -- a
 * one-liner here, a runnable shell command there, an env-var explanation
 * somewhere else. A shell command sitting in an empty panel reads as an
 * unfinished dev tool in front of anyone this gets demoed to; that kind of
 * detail belongs in docs, not in the UI.
 */
export function EmptyState({ icon: Icon = EmptyIcon, title, hint }) {
  return (
    <div className="empty-state">
      <Icon size={22} aria-hidden="true" />
      <p>{title}</p>
      {hint ? <small>{hint}</small> : null}
    </div>
  );
}

/** One loading primitive, replacing five-plus inconsistently-capitalized ad
 * hoc strings ("Loading map…", "loading…", "Loading {ip}…", ...). */
export function Loading({ label = "Loading…" }) {
  return (
    <span className="loading">
      <SpinnerIcon size={14} className="spin" aria-hidden="true" />
      {label}
    </span>
  );
}

// Status-chip tone: this app's own status codes, not a signal or policy
// action, so it gets its own small mapping rather than reusing riskTone.
function statusTone(status) {
  const code = Number(status);
  if (code === 429) return "warn";
  if (code >= 400) return "bad";
  return "ok";
}

// The Action column's own tone -- deliberately not the shared ACTION_TONE
// (--risk .low/.mid/.high) that Policy and Campaigns use for the same
// action names, because those two disagree on what "monitor" should look
// like: ACTION_TONE paints it green (low risk), the design calls for it
// muted/dim here. Same word, different column, different meaning: whether
// this row saw enforcement, not how risky the address is.
const EVENT_ACTION_TONE = {
  temp_block: "bad",
  temporary_block: "bad",
  escalate: "bad",
  throttle: "warn",
  rate_limited: "warn",
  monitor: "dim",
};

export function EventTable({ events, empty, showRequestNumber = false, showGeo = false, geoByIp = {} }) {
  const cols = 7 + (showRequestNumber ? 1 : 0) + (showGeo ? 1 : 0);
  const [selectedEvent, setSelectedEvent] = useState(null);
  return (
    <>
      <div className="table-wrap">
        <table>
        <thead>
          <tr>
            {showRequestNumber ? <th>Req no.</th> : null}
            <th>Time ({DISPLAY_TIME_ZONE_LABEL})</th>
            <th>Source</th>
            {showGeo ? <th>Geo</th> : null}
            <th>Endpoint</th>
            <th>Status</th>
            <th>Risk</th>
            <th>Matched signals</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {events.length === 0 ? (
            <tr>
              <td colSpan={cols} className="empty">
                {empty}
              </td>
            </tr>
          ) : (
            events.map((event) => {
              const risk = clampRiskScore(event.riskScore);
              const tone = riskTone(risk);
              const actionTone = EVENT_ACTION_TONE[event.decision] || "ok";
              return (
                <tr
                  key={event.id || event.requestId}
                  className={event.fired?.length ? "alert-row" : ""}
                >
                  {showRequestNumber ? <td className="mono">{event.seq ?? "—"}</td> : null}
                  <td className="mono">{formatTime(event.ts)}</td>
                  <td>
                    <IpLink ip={event.ip} />
                  </td>
                  {showGeo ? <td>{geoByIp[event.ip] || "—"}</td> : null}
                  <td>
                    <span className="method">{event.method}</span> {event.path}
                  </td>
                  <td>
                    <button
                      type="button"
                      className={`status-chip status-button ${statusTone(event.status)}`}
                      onClick={() => setSelectedEvent(event)}
                      title="View request details"
                    >
                      {event.status}
                    </button>
                  </td>
                  <td>
                    <div className="risk-cell">
                      <span className={`risk ${tone}`}>{risk}</span>
                      <span className="risk-meter">
                        <span className={`risk-meter-fill ${tone}`} style={{ width: `${risk}%` }} />
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="sig-tags">
                      {(event.fired || []).length === 0 ? (
                        <span className="faint">—</span>
                      ) : (
                        canonicalSignals(event.fired).map((name) => {
                          const meta = signalMeta(name);
                          return (
                            <span
                              key={name}
                              className="sig-tag"
                              style={{ color: meta.color, borderColor: meta.color }}
                            >
                              {meta.label}
                            </span>
                          );
                        })
                      )}
                    </div>
                  </td>
                  <td>
                    <span className={`event-action ${actionTone}`}>{actionLabel(event.decision)}</span>
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
        </table>
      </div>
      {selectedEvent ? <EventDetails event={selectedEvent} onClose={() => setSelectedEvent(null)} /> : null}
    </>
  );
}

function EventDetails({ event, onClose }) {
  const retryAfter = event.status === 429
    ? event.retryAfter || "Not recorded for this event"
    : "Not applicable";
  const fields = [
    ["Request ID", event.requestId],
    ["Request number", event.seq],
    ["Arrived", event.arrivalTs && formatTime(event.arrivalTs)],
    ["Completed", event.ts && formatTime(event.ts)],
    ["Source IP", event.ip],
    ["User agent", event.userAgent],
    ["Endpoint", [event.method, event.path].filter(Boolean).join(" ")],
    ["Route template", event.routeTemplate],
    ["Query", event.query],
    ["Status", event.status],
    ["Retry-After", retryAfter],
    ["Response origin", event.responseOrigin],
    ["Gateway reason", event.gatewayReason],
    ["Decision", actionLabel(event.decision)],
    ["Risk score", event.riskScore],
    ["Upstream status", event.upstreamStatus],
    ["Upstream outcome", event.upstreamOutcome],
    ["Upstream duration", event.upstreamDurationMs != null ? `${event.upstreamDurationMs} ms` : null],
    ["Gateway duration", event.gatewayMs != null ? `${event.gatewayMs} ms` : null],
    ["Request body", event.requestBodyBytes != null ? `${event.requestBodyBytes} bytes` : null],
    ["Response body", event.responseBodyBytes != null ? `${event.responseBodyBytes} bytes` : null],
  ];

  return (
    <div className="modal-overlay" onMouseDown={onClose}>
      <section
        className="modal-card event-details-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="event-details-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="event-details-head">
          <div>
            <p className="eyebrow">Request inspection</p>
            <h2 id="event-details-title">Request details</h2>
          </div>
          <button type="button" className="act small" onClick={onClose}>Close</button>
        </div>
        <div className="event-details-signals">
          {(event.fired || []).length
            ? canonicalSignals(event.fired).map((name) => {
              const meta = signalMeta(name);
              return <span key={name} className="sig-tag" style={{ color: meta.color, borderColor: meta.color }}>{meta.label}</span>;
            })
            : <span className="faint">No detector signals</span>}
        </div>
        <dl className="event-details-grid">
          {fields.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd>{value === undefined || value === null || value === "" ? "—" : String(value)}</dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  );
}

/**
 * An address, linked to everything known about it.
 *
 * Used everywhere an IP appears, so the route into the investigation view is
 * the same wherever you notice the address.
 */
export function IpLink({ ip, className = "mono" }) {
  if (!ip) return <span className={className}>—</span>;
  return (
    <Link href={`/ip/${encodeURIComponent(ip)}`} className={className} title={`Everything known about ${ip}`}>
      {ip}
    </Link>
  );
}

/** Download the current view. Disabled when there is nothing in it. */
export function ExportMenu({ rows, columns, prefix, label = "export" }) {
  const count = rows?.length || 0;
  return (
    <span className="export-menu no-snapshot">
      <button
        type="button"
        className="act"
        disabled={!count}
        onClick={() => exportCsv(prefix, rows, columns)}
        title={count ? `Download these ${count} rows as CSV` : "Nothing to export"}
      >
        {label} csv
      </button>
      <button
        type="button"
        className="act"
        disabled={!count}
        onClick={() => exportJson(prefix, rows)}
        title={count ? `Download these ${count} rows as JSON` : "Nothing to export"}
      >
        json
      </button>
    </span>
  );
}

/**
 * A PNG of the whole page section `targetRef` points at -- the page's own
 * card, filters and list included, not just the row data an export gets.
 * Meant for a panel: something to paste into a slide or a chat, not to feed
 * back into anything.
 */
// `beforeCapture`/`afterCapture` let a page change its own rendering for the
// capture -- Events uncaps rows load, capping them a different way instead --
// and must be awaited before/after so the DOM the capture reads is the one
// those changes produced, not whatever was on screen when the button was
// clicked.
export function SnapshotButton({ targetRef, prefix, title, beforeCapture, afterCapture }) {
  const { setToast } = useLive();
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      await beforeCapture?.();
      await snapshotPng(targetRef.current, prefix);
    } catch (err) {
      setToast({ tone: "bad", text: `snapshot failed: ${err.message}` });
    } finally {
      await afterCapture?.();
      setBusy(false);
    }
  }

  return (
    <button
      type="button"
      className="act no-snapshot"
      disabled={busy}
      onClick={run}
      title={title || "Download a PNG of this whole view"}
    >
      {busy ? "capturing…" : "snapshot"}
    </button>
  );
}
