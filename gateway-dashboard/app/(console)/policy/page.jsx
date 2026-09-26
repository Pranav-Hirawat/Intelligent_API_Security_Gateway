"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { PageHead } from "@/app/ui/chrome";
import { ACTION_TONE, LADDER, actionLabel, formatTtl, normalizeAction } from "@/app/ui/format";
import { useLive } from "@/app/ui/store";
import { DecisionExplanation, ExportMenu, IpFilterField, Metric, SnapshotButton } from "@/app/ui/parts";
import { POLICY_COLUMNS } from "@/app/ui/export";

export default function PolicyPage() {
  const {
    policies, escalations, learned, busy, pendingPolicyActions, instruct, deletePolicy,
  } = useLive();
  const [ip, setIp] = useState("");
  const [action, setAction] = useState("temp_block");
  const [reason, setReason] = useState("");
  const [sort, setSort] = useState("expiry");
  const [filterIp, setFilterIp] = useState("");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const snapRef = useRef(null);

  useEffect(() => {
    if (!advancedOpen) return undefined;
    const closeOnEscape = (event) => {
      if (event.key === "Escape") setAdvancedOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [advancedOpen]);

  const rows = [...policies]
    .filter((policy) => !filterIp || policy.ip === filterIp)
    .sort((a, b) => (sort === "expiry" ? a.expiresIn - b.expiresIn : b.confidence - a.confidence));

  const blocked = policies.filter(
    (policy) => policy.action === "temp_block" || policy.action === "temporary_block",
  ).length;
  const expiringSoon = policies.filter(
    (policy) => policy.expiresIn != null && policy.expiresIn >= 0 && policy.expiresIn <= 3600,
  ).length;

  async function submit(event) {
    event.preventDefault();
    const ok = await instruct([ip.trim()], action, "manual", reason.trim());
    if (ok) {
      setIp("");
      setReason("");
    }
  }

  async function removePolicy(policy) {
    if (!window.confirm(
      `Remove all ${policy.policyCount || 1} active policy scope${policy.policyCount === 1 ? "" : "s"} for ${policy.ip}? ` +
      "This takes effect immediately. The agent can recreate them if the campaign remains active.",
    )) return;
    await deletePolicy(policy.ip);
  }

  return (
    <div ref={snapRef} className="page-body">
      <PageHead eyebrow="Enforcement" title="Policy">
        What the gateway is currently enforcing. Human instructions go to the override stream
        and are applied on the next agent cycle, after the same allowlist and collateral checks
        as the agent&apos;s own decisions.
      </PageHead>

      <section className="policy-advanced-launch" aria-label="Human review controls">
        <div>
          <strong>Need to correct or review the agent?</strong>
          <span>Send a manual instruction or inspect what the agent learned from past corrections.</span>
        </div>
        <button type="button" className="act" onClick={() => setAdvancedOpen(true)}>
          Human Review / Advanced
        </button>
      </section>

      <section className="metrics">
        <Metric label="Protected addresses" value={policies.length} detail="one combined row per identity" />
        <Metric label="Blocked addresses" value={blocked} detail="temp block, right now" />
        <Metric label="Expiring within the hour" value={expiringSoon} detail="TTL running out" />
        <Metric label="Escalated to you" value={escalations.length} detail="raised once per campaign" />
      </section>

      <p className="form-note">
        Delete policy removes the current Redis policy key immediately. It does not end the
        underlying campaign, so the agent may create a new policy on a later cycle.
      </p>

      <section className="policy-in-force">
        <article className="card panel-primary">
          <div className="card-head">
            <h2>In force</h2>
            <ExportMenu rows={rows} columns={POLICY_COLUMNS} prefix="policy" />
            <SnapshotButton targetRef={snapRef} prefix="policy" title="Download a PNG of this policy view" />
            <div className="head-controls">
              <IpFilterField value={filterIp} onChange={setFilterIp} placeholder="Only this IP..." />
              <label className="field">
                Sort
                <select value={sort} onChange={(event) => setSort(event.target.value)}>
                  <option value="expiry">expiring first</option>
                  <option value="confidence">confidence</option>
                </select>
              </label>
              <span className="count">
                {filterIp ? `${rows.length}/${policies.length}` : policies.length}
              </span>
            </div>
          </div>

          {rows.length === 0 ? (
            <p className="empty">
              {filterIp
                ? `No active policy for ${filterIp}.`
                : "No policy keys written. The gateway is observing but not enforcing."}
            </p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>#</th><th>Scope</th><th>Condition</th><th>Action</th><th>Expires</th>
                    <th>Origin</th><th>State</th><th>Change to</th><th>Remove</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((policy, index) => (
                    <tr key={policy.policyId || policy.ip}>
                      <td className="mono">{String(index + 1).padStart(2, "0")}</td>
                      <td>
                        <Link href={`/events?ip=${encodeURIComponent(policy.ip)}`} className="mono">
                          {policy.ip}
                        </Link>
                      </td>
                      <td>
                        <strong>{(policy.scopes || [policy.method && policy.routeTemplate ? `${policy.method} ${policy.routeTemplate}` : "Any request"]).join(" + ")}</strong>
                        {policy.policyCount > 1 ? (
                          <small className="scope-line">{policy.policyCount} active Redis policy keys combined for this address</small>
                        ) : null}
                        {policy.reason ? <small className="scope-line">{policy.reason}</small> : null}
                        <DecisionExplanation
                          explanation={policy.explanation}
                          riskScore={policy.riskScore}
                          confidence={policy.confidence}
                        />
                      </td>
                      <td><span className={`risk ${ACTION_TONE[policy.action] || "low"}`}>{actionLabel(policy.action)}</span></td>
                      <td className="mono">{formatTtl(policy.expiresIn)}</td>
                      <td>
                        {policy.source === "human" ? <span className="tag">human</span>
                          : policy.campaignId && policy.campaignId !== "manual" ? <Link href="/campaigns">campaign #{policy.campaignId}</Link>
                            : <span className="tag">agent</span>}
                      </td>
                      <td><span className="tag good">Active{policy.policyCount > 1 ? ` · ${policy.policyCount} scopes` : ""}</span></td>
                      <td>
                        <div className="row-actions">
                          {pendingPolicyActions[policy.ip] ? (
                            <span className="tag">changing to {actionLabel(pendingPolicyActions[policy.ip])}...</span>
                          ) : LADDER.filter((nextAction) => nextAction !== normalizeAction(policy.action)).map((nextAction) => (
                            <button
                              key={nextAction}
                              type="button"
                              className="act small"
                              disabled={Boolean(busy)}
                              onClick={() => instruct([policy.ip], nextAction, `row-${policy.ip}`)}
                              title={`Instruct ${actionLabel(nextAction)} for ${policy.ip}`}
                            >
                              {busy === `row-${policy.ip}:${nextAction}` ? "..." : actionLabel(nextAction)}
                            </button>
                          ))}
                        </div>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="act danger small"
                          disabled={Boolean(busy)}
                          onClick={() => removePolicy(policy)}
                          title={`Remove the active policy for ${policy.ip}`}
                        >
                          {busy === `delete-policy:${policy.ip}` ? "Removing..." : "Delete policy"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </article>
      </section>

      {advancedOpen ? (
        <div className="modal-overlay" onMouseDown={() => setAdvancedOpen(false)}>
          <section
            className="modal-card policy-advanced-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="human-review-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="policy-advanced-head">
              <div>
                <p className="eyebrow">Human control</p>
                <h2 id="human-review-title">Human Review / Advanced</h2>
                <p>Manual instructions take effect on the next agent cycle; they do not write a gateway policy directly.</p>
              </div>
              <button type="button" className="act small" onClick={() => setAdvancedOpen(false)} aria-label="Close human review">
                Close
              </button>
            </div>

            <div className="policy-advanced-grid">
              <article className="card">
                <div className="card-head"><h2>Instruct the agent</h2><span>Any address, campaign or not</span></div>
                <form className="form" onSubmit={submit}>
                  <label className="field block">Address
                    <input type="text" value={ip} onChange={(event) => setIp(event.target.value)} placeholder="203.0.113.5" required />
                  </label>
                  <label className="field block">Action
                    <select value={action} onChange={(event) => setAction(event.target.value)}>
                      {LADDER.map((nextAction) => <option key={nextAction} value={nextAction}>{actionLabel(nextAction)}</option>)}
                    </select>
                  </label>
                  <label className="field block">Reason
                    <input type="text" value={reason} onChange={(event) => setReason(event.target.value)} placeholder="confirmed attack" />
                  </label>
                  <button type="submit" className="act primary" disabled={Boolean(busy) || !ip.trim()}>
                    {busy?.startsWith("manual") ? "Sending..." : `Instruct ${actionLabel(action)}`}
                  </button>
                  <p className="form-note">
                    An allowlisted range is protected from a mistyped instruction. <b>{actionLabel("monitor")}</b> stops future enforcement; it does not clear a policy that already exists.
                  </p>
                </form>
              </article>

              <div className="policy-advanced-stack">
                {escalations.length > 0 ? (
                  <article className="card">
                    <div className="card-head"><h2>Escalated</h2><span>Raised once per campaign</span></div>
                    <ul className="policy-list">
                      {escalations.map((escalation) => (
                        <li key={escalation.id}>
                          <div className="policy-top"><Link href="/campaigns">#{escalation.campaignId}</Link><span className="risk high">{escalation.ipCount} IPs</span></div>
                          <small>{escalation.type} - confidence {escalation.confidence.toFixed(2)}</small>
                        </li>
                      ))}
                    </ul>
                  </article>
                ) : null}

                <article className="card">
                  <div className="card-head"><h2>Learned from humans</h2><span>One rung, never more</span></div>
                  {learned.length === 0 ? (
                    <p className="empty">Nothing learned yet. Overrule the agent twice in the same direction on one campaign type and it starts making that correction itself.</p>
                  ) : (
                    <ul className="policy-list">
                      {learned.map((row) => (
                        <li key={row.type}>
                          <div className="policy-top"><span className="grow">{row.type}</span><span className={`risk ${row.net > 0 ? "high" : "low"}`}>{row.net > 0 ? "stronger" : "weaker"}</span></div>
                          <small>+{row.up} / -{row.down} corrections</small>
                        </li>
                      ))}
                    </ul>
                  )}
                </article>
              </div>
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}
