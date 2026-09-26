"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { PageHead } from "@/app/ui/chrome";
import { actionLabel, formatTime } from "@/app/ui/format";
import { DecisionExplanation, Field } from "@/app/ui/parts";
import { MODE_OPTIONS } from "@/lib/adaptive-mode.mjs";

const ACTIONS = ["monitor", "throttle", "temp_block"];

export default function AdaptivePage() {
  const [data, setData] = useState({
    baselines: [],
    recommendations: [],
    audit: [],
    activePolicies: [],
  });
  const [draft, setDraft] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [advancedSection, setAdvancedSection] = useState("guardrails");
  const [confirmAdvancedSave, setConfirmAdvancedSave] = useState(false);
  const [savedConfig, setSavedConfig] = useState(null);

  const load = useCallback(async () => {
    const response = await fetch("/api/adaptive", { cache: "no-store" });
    const value = await response.json();
    setData(value);
    if (value.config) setDraft((current) => current || structuredClone(value.config));
    setError(value.available ? "" : value.error || "adaptive store unavailable");
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [load]);

  const pending = useMemo(
    () => data.recommendations?.filter((row) => row.status === "pending_approval") || [],
    [data.recommendations],
  );
  const effectiveMode = data.config?.mode || draft?.mode || "monitor";
  const selectedMode = draft?.mode || effectiveMode;
  const savedMode = MODE_OPTIONS.find((option) => option.value === effectiveMode);

  async function saveConfig(config, key) {
    setBusy(key);
    const response = await fetch("/api/adaptive/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    });
    const value = await response.json();
    setBusy("");
    if (!response.ok) {
      setError(value.error || "settings rejected");
      return false;
    }
    setData((current) => ({ ...current, config: value.config }));
    setDraft(structuredClone(value.config));
    setSavedConfig(value.config);
    await load();
    return true;
  }

  function saveChoices() {
    if (!data.config || !draft) return;
    saveConfig({
      ...structuredClone(data.config),
      mode: draft.mode,
      guardrails: {
        ...data.config.guardrails,
        maximum_automatic_action: draft.guardrails.maximum_automatic_action,
        behavioural_throttle_enabled: draft.guardrails.behavioural_throttle_enabled,
      },
    }, "choices");
  }

  async function decide(row, decision) {
    const action = document.getElementById("action-" + row.policyId)?.value || row.action;
    const rpm = Number(
      document.getElementById("rpm-" + row.policyId)?.value || row.requestsPerMinute || 0,
    );
    const duration = Number(document.getElementById("duration-" + row.policyId)?.value || 900);
    setBusy(row.policyId);
    const response = await fetch("/api/adaptive/recommendations/" + encodeURIComponent(row.policyId), {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        decision,
        edits:
          decision === "approve"
            ? {
                action,
                requests_per_minute: action === "throttle" ? rpm : 0,
                duration_seconds: duration,
              }
            : {},
      }),
    });
    const value = await response.json();
    setBusy("");
    if (!response.ok) return setError(value.error || "decision rejected");
    await load();
  }

  function edit(section, name, value) {
    setDraft((current) => ({ ...current, [section]: { ...current[section], [name]: value } }));
  }

  async function saveAdvancedSettings() {
    if (await saveConfig(draft, "advanced")) setConfirmAdvancedSave(false);
  }

  // One row per plain numeric setting: [key, label, step?].
  const numberFields = (section, rows) => rows.map(([name, label, step]) => (
    <Field.Number
      key={name}
      label={label}
      step={step}
      value={draft[section][name]}
      onChange={(value) => edit(section, name, Number(value))}
    />
  ));

  return (
    <>
      <PageHead title="Adaptive enforcement">
        Choose how approved recommendations may be enforced.
      </PageHead>

      {error ? <p className="notice bad">{error}</p> : null}

      {draft ? (
        <section className="card mode-overview">
          <div className="mode-banner">
            <div>
              <p className="eyebrow">Enforcement</p>
              <h2>How should recommendations be applied?</h2>
              <p>Learning always stays on; this only controls policy creation.</p>
            </div>
            <span className="tag good">Saved: {savedMode?.label || "Monitor"}</span>
          </div>

          <fieldset className="mode-cards" aria-label="Enforcement mode">
            <legend>Choose a mode</legend>
            {MODE_OPTIONS.map((option) => (
              <label
                key={option.value}
                className={"mode-card" + (selectedMode === option.value ? " selected" : "")}
              >
                <input
                  type="radio"
                  name="enforcement-mode"
                  value={option.value}
                  checked={selectedMode === option.value}
                  onChange={() => setDraft({ ...draft, mode: option.value })}
                />
                <strong>{option.label}</strong>
                <span>
                  {option.value === "monitor"
                    ? "Review only"
                    : option.value === "manual"
                      ? "Require approval"
                      : "Apply within limits"}
                </span>
              </label>
            ))}
          </fieldset>

          <p className="mode-summary">Policies always expire; detailed guardrails are under Advanced settings.</p>

          {selectedMode === "automatic" ? (
            <div className="automatic-safeguards">
              <label>
                <span>Automatic action cap</span>
                <select
                  value={draft.guardrails.maximum_automatic_action}
                  onChange={(event) => edit("guardrails", "maximum_automatic_action", event.target.value)}
                >
                  {ACTIONS.map((action) => (
                    <option key={action} value={action}>{actionLabel(action)}</option>
                  ))}
                </select>
              </label>
              <label className="compact-toggle">
                <input
                  type="checkbox"
                  checked={Boolean(draft.guardrails.behavioural_throttle_enabled)}
                  onChange={(event) => edit("guardrails", "behavioural_throttle_enabled", event.target.checked)}
                />
                <span>Use learned endpoint rates for throttling</span>
              </label>
            </div>
          ) : null}

          <button className="act primary" type="button" disabled={Boolean(busy)} onClick={saveChoices}>
            {busy === "choices" ? "Saving..." : "Save selection"}
          </button>
        </section>
      ) : null}

      {pending.length ? (
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Pending recommendations</h2>
            <p className="section-note">
              {effectiveMode === "manual"
                ? "An analyst must approve, edit, or reject these before enforcement."
                : "Shown for investigation; only Manual mode creates approvals that await an analyst."}
            </p>
          </div>
          <span>{pending.length}</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Target / scope</th>
                <th>Risk</th>
                <th>Policy confidence</th>
                <th>Action</th>
                <th>RPM</th>
                <th>Duration</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {pending.map((row) => (
                  <tr key={row.policyId}>
                    <td className="mono">
                      {row.targetIdentity}
                      <small className="scope-line">
                        {row.method} {row.routeTemplate}
                      </small>
                      <DecisionExplanation explanation={row.explanation} riskScore={row.riskScore} confidence={row.confidence} />
                    </td>
                    <td>{row.riskScore.toFixed(1)}</td>
                    <td>{row.confidence.toFixed(3)}</td>
                    <td>
                      <select id={"action-" + row.policyId} defaultValue={row.action}>
                        {ACTIONS.map((action) => (
                          <option key={action} value={action}>
                            {actionLabel(action)}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <input
                        id={"rpm-" + row.policyId}
                        type="number"
                        defaultValue={row.requestsPerMinute || draft?.guardrails.default_throttle_rpm || 60}
                      />
                    </td>
                    <td>
                      <input
                        id={"duration-" + row.policyId}
                        type="number"
                        defaultValue={draft?.guardrails.throttle_duration_seconds || 900}
                      />
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="act small"
                          disabled={Boolean(busy)}
                          onClick={() => decide(row, "approve")}
                        >
                          Approve / edit
                        </button>
                        <button
                          className="act danger small"
                          disabled={Boolean(busy)}
                          onClick={() => decide(row, "reject")}
                        >
                          Reject
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </section>
      ) : null}

      {!pending.length && !data.baselines?.length && !data.audit?.length ? (
        <section className="card adaptive-empty-state">
          <div>
            <h2>No adaptive activity yet</h2>
            <p>Recommendations, learned endpoints, and the audit trail will appear here when available.</p>
          </div>
          <div className="activity-counts" aria-label="Adaptive activity counts">
            <span>0 pending</span>
            <span>0 endpoints</span>
            <span>0 audit events</span>
          </div>
        </section>
      ) : null}

      {data.baselines?.length ? (
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Endpoint learning</h2>
            <p className="section-note">Learning stays active in every mode.</p>
          </div>
          <span>{data.baselines?.length || 0} normalized endpoints</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>State</th>
                <th>Samples</th>
                <th>Observed RPM</th>
                <th>Median</th>
                <th>MAD</th>
                <th>Threshold</th>
                <th>Updated (IST)</th>
              </tr>
            </thead>
            <tbody>
              {data.baselines.map((row) => (
                  <tr key={row.method + " " + row.routeTemplate}>
                    <td>
                      <span className="method">{row.method}</span> {row.routeTemplate}
                    </td>
                    <td>
                      <span className={"tag " + (row.ready ? "good" : "")}>
                        {row.ready ? "ready" : "warming up"}
                      </span>
                    </td>
                    <td>{row.sampleCount}</td>
                    <td>{row.observedRate}</td>
                    <td>{row.statistic.toFixed(1)}</td>
                    <td>{row.mad.toFixed(1)}</td>
                    <td>{row.threshold}</td>
                    <td>{formatTime(row.lastUpdate)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </section>
      ) : null}

      {data.audit?.length ? (
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Audit history (IST)</h2>
            <p className="section-note">Durable record of recommendations, approvals, overrides, and settings.</p>
          </div>
          <span>{data.audit?.length || 0}</span>
        </div>
        <ul className="audit-list">
          {data.audit?.length ? (
            data.audit.map((row) => (
              <li key={row.auditId}>
                <b>{row.event}</b> · {row.policyId}
                <small>
                  {row.actor} · {formatTime(row.createdAt)}
                </small>
              </li>
            ))
          ) : (
            <li className="empty">No adaptive audit events yet.</li>
          )}
        </ul>
      </section>
      ) : null}

      {draft ? (
        <details className="card advanced-settings">
          <summary>Advanced settings</summary>
          <p className="section-note">
            Tune one category at a time. Changes are versioned and checked before saving.
          </p>

          <div className="advanced-tabs" role="tablist" aria-label="Advanced setting categories">
            {[
              ["guardrails", "Policy guardrails"],
              ["baseline", "Baseline learning"],
              ["risk", "Risk tuning"],
            ].map(([value, label]) => (
              <button
                key={value}
                type="button"
                role="tab"
                aria-selected={advancedSection === value}
                className={advancedSection === value ? "on" : ""}
                onClick={() => setAdvancedSection(value)}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="advanced-groups">
            <section hidden={advancedSection !== "guardrails"}>
              <h3>Policy guardrails</h3>
              <div className="guardrail-grid">
                {numberFields("guardrails", GUARDRAIL_LIMITS)}
                <Field.Number
                  label="Behavioural throttle minimum deviation"
                  step="0.1"
                  value={draft.guardrails.behavioural_throttle_minimum_deviation ?? 2}
                  hint="Only a ready endpoint baseline exceeding this ratio can create a throttle; blocks still require detector evidence."
                  onChange={(value) => edit("guardrails", "behavioural_throttle_minimum_deviation", Number(value))}
                />
                {numberFields("guardrails", GUARDRAIL_EVIDENCE)}
                <Field.Textarea
                  label="Emergency allowlist (address/CIDR per line)"
                  value={draft.guardrails.allowlist.join("\n")}
                  onChange={(value) => edit("guardrails", "allowlist", splitRanges(value))}
                />
                <Field.Textarea
                  label="Emergency blocklist (address/CIDR per line)"
                  value={draft.guardrails.blocklist.join("\n")}
                  onChange={(value) => edit("guardrails", "blocklist", splitRanges(value))}
                />
              </div>
            </section>

            <section hidden={advancedSection !== "baseline"}>
              <h3>Baseline learning</h3>
              <div className="guardrail-grid">
                {numberFields("baseline", BASELINE_NUMBERS)}
              </div>
            </section>

            <section hidden={advancedSection !== "risk"}>
              <h3>Risk and confidence tuning</h3>
              <div className="guardrail-grid">
                {numberFields("risk", RISK_NUMBERS)}
              </div>
            </section>
          </div>

          <button
            className="act primary"
            type="button"
            disabled={Boolean(busy)}
            onClick={() => setConfirmAdvancedSave(true)}
          >
            {busy === "advanced" ? "Saving advanced settings..." : "Save advanced settings"}
          </button>
        </details>
      ) : null}

      {confirmAdvancedSave ? (
        <div className="modal-overlay" onMouseDown={() => !busy && setConfirmAdvancedSave(false)}>
          <section
            className="modal-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="save-advanced-settings-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <h2 id="save-advanced-settings-title">Save advanced settings?</h2>
            <p>
              This updates policy guardrails, baseline learning, and risk tuning for the control
              plane. The server will reject invalid or outdated changes.
            </p>
            <div className="modal-actions">
              <button type="button" className="act" disabled={Boolean(busy)} onClick={() => setConfirmAdvancedSave(false)}>
                Cancel
              </button>
              <button type="button" className="act primary" disabled={Boolean(busy)} onClick={saveAdvancedSettings}>
                {busy === "advanced" ? "Saving..." : "Save settings"}
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {savedConfig ? (
        <div className="modal-overlay" onMouseDown={() => setSavedConfig(null)}>
          <section
            className="modal-card adaptive-saved-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="adaptive-settings-saved-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <p className="eyebrow">Saved</p>
            <h2 id="adaptive-settings-saved-title">Settings saved</h2>
            <p>
              Adaptive configuration v{savedConfig.version} is now stored. The control plane uses it
              on its next cycle.
            </p>
            <div className="modal-actions">
              <button type="button" className="act primary" onClick={() => setSavedConfig(null)} autoFocus>
                Continue
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}

// Plain numeric settings, in the order the form shows them.
const GUARDRAIL_LIMITS = [
  ["maximum_policy_duration_seconds", "Maximum policy duration (seconds)"],
  ["monitor_duration_seconds", "Monitor duration (seconds)"],
  ["throttle_duration_seconds", "Throttle duration (seconds)"],
  ["temporary_block_duration_seconds", "Temporary-block duration (seconds)"],
  ["minimum_confidence_throttle", "Throttle confidence", "0.01"],
  ["minimum_confidence_temporary_block", "Temporary-block confidence", "0.01"],
  ["minimum_throttle_rpm", "Minimum throttle RPM"],
  ["default_throttle_rpm", "Default throttle RPM"],
  ["maximum_throttle_rpm", "Maximum throttle RPM"],
  ["throttle_baseline_fraction", "Throttle baseline fraction", "0.01"],
];

const GUARDRAIL_EVIDENCE = [
  ["policy_cooldown_seconds", "Policy cooldown (seconds)"],
  ["minimum_deterministic_evidence_throttle", "Evidence required: throttle"],
  ["minimum_deterministic_evidence_temporary_block", "Evidence required: temporary block"],
];

const BASELINE_NUMBERS = [
  ["warmup_windows", "Warm-up windows"],
  ["rolling_windows", "Rolling windows"],
  ["mad_multiplier", "MAD multiplier", "0.1"],
  ["minimum_mad", "Minimum MAD", "0.1"],
  ["minimum_threshold_rpm", "Minimum learned RPM"],
  ["maximum_threshold_rpm", "Maximum learned RPM"],
  ["hysteresis_ratio", "Baseline hysteresis", "0.01"],
  ["cooldown_seconds", "Threshold cooldown (seconds)"],
];

const RISK_NUMBERS = [
  ["deterministic_weight", "Deterministic risk weight", "0.01"],
  ["behavioural_weight", "Behavioural risk weight", "0.01"],
  ["campaign_weight", "Campaign risk weight", "0.01"],
  ["throttle_score", "Throttle risk score", "0.1"],
  ["temporary_block_score", "Temporary-block risk score", "0.1"],
];

function splitRanges(value) {
  return value
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}
