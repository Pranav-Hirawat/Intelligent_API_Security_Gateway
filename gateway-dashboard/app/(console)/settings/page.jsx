"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { PageHead, ResetControl } from "@/app/ui/chrome";
import { Field } from "@/app/ui/parts";
import { useLive } from "@/app/ui/store";

// These names are the gateway's enforcement vocabulary, not presentation
// labels. Keeping it beside the switches prevents a friendly label from
// accidentally arming a detector name the gateway never emits.
const DETECTORS = [
  { section: "rate_limit", name: "API flooding", signal: "api_flooding", blockName: "api_flooding", summary: (d) => `${d.rate_limit.requests_per_minute} req/min` },
  { section: "attack_detection", name: "SQL injection", signal: "sql_injection", blockName: "sql_injection", summary: (d) => `${(d.attack_detection.sql_patterns || []).length} signatures` },
  { section: "brute_force", name: "Failed logins", signal: "consecutive_failed_logins", summary: (d) => `${d.brute_force.max_failures} failures · ${d.brute_force.window}` },
  { section: "unknown_route_scanning", name: "Route scanning", signal: "unknown_route_scanning", summary: (d) => `${d.unknown_route_scanning.distinct_paths} paths · ${d.unknown_route_scanning.window}` },
  { section: "object_enumeration", name: "Object ID enumeration (BOLA)", signal: "object_enumeration", summary: (d) => `${d.object_enumeration.distinct_ids} ids · ${d.object_enumeration.window}` },
  { section: "object_ownership", name: "Ownership check (BOLA)", signal: "ownership_violation", summary: (d) => `unreadable responses: ${d.object_ownership.on_unverifiable === "allow" ? "passed" : "refused"}` },
  { section: "enumeration_path_traversal", name: "Traversal & enumeration", signal: "enumeration_path_traversal", blockName: "enumeration_path_traversal", summary: (d) => `${(d.enumeration_path_traversal.traversal_patterns || []).length} traversal · ${(d.enumeration_path_traversal.enumeration_patterns || []).length} paths` },
  { section: "ip_reputation", name: "Known bad addresses", signal: "ip_reputation", blockName: "ip_reputation", summary: (d) => `score ${d.ip_reputation.score} · ${d.ip_reputation.cooldown}` },
];

export default function SettingsPage() {
  const { setToast, stats } = useLive();
  const [saved, setSaved] = useState(null);
  const [draft, setDraft] = useState(null);
  const [source, setSource] = useState("file");
  const [readOnly, setReadOnly] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(null);
  const [confirmText, setConfirmText] = useState("");

  const load = useCallback(async () => {
    try {
      const response = await fetch("/api/settings");
      const data = await response.json();
      if (!response.ok || !data.ok) {
        setError(data.error || `could not read settings (${response.status})`);
        return null;
      }
      setError(null);
      setSaved(data.settings);
      setSource(data.source);
      setReadOnly(data.readOnly || null);
      return data.settings;
    } catch (err) {
      setError(`could not reach the server: ${err.message}`);
      return null;
    }
  }, []);

  useEffect(() => {
    load().then((settings) => settings && setDraft(structuredClone(settings)));
  }, [load]);

  const dirty = draft && saved && JSON.stringify(draft) !== JSON.stringify(saved);
  // A gateway older than a detector sends no section for it; show what it runs.
  const detectors = draft ? DETECTORS.filter((detector) => draft[detector.section]) : [];
  const byName = Object.fromEntries(detectors.map((detector) => [detector.section, detector]));
  const enabledCount = detectors.filter((detector) => draft[detector.section].enabled).length;
  const autoBlockCount = draft
    ? detectors.filter((detector) => detector.blockName && draft.block.enabled && draft.block.signals?.includes(detector.blockName)).length
    : 0;
  const alertsFor = useMemo(() => (signal) => (stats.signals?.[signal] || 0).toLocaleString(), [stats.signals]);

  function edit(section, key, value) {
    setDraft((current) => ({ ...current, [section]: { ...current[section], [key]: value } }));
  }

  function toggleBlock(name) {
    setDraft((current) => {
      const signals = current.block.signals || [];
      const next = signals.includes(name) ? signals.filter((signal) => signal !== name) : [...signals, name];
      return { ...current, block: { ...current.block, signals: next } };
    });
  }

  function closeConfirmation() {
    setConfirming(null);
    setConfirmText("");
  }

  async function apply() {
    setBusy(true);
    try {
      const response = await fetch("/api/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm: "apply", settings: draft }),
      });
      const data = await response.json();
      if (!response.ok || !data.ok) {
        setToast({ tone: "bad", text: data.error || `save failed (${response.status})` });
        return;
      }
      closeConfirmation();
      setToast({ tone: "good", text: "sent to the gateway — waiting for it to apply" });
      setTimeout(async () => {
        const now = await load();
        if (!now) return;
        if (JSON.stringify(now) === JSON.stringify(draft)) {
          setToast({ tone: "good", text: "the gateway is enforcing the new protection settings" });
        } else {
          setToast({ tone: "bad", text: "the gateway rejected part of the change" });
          setDraft(structuredClone(now));
        }
      }, 6000);
    } catch (err) {
      setToast({ tone: "bad", text: `could not reach the server: ${err.message}` });
    } finally {
      setBusy(false);
    }
  }

  async function revert() {
    setBusy(true);
    try {
      const response = await fetch("/api/settings", { method: "DELETE" });
      const data = await response.json();
      if (!response.ok || !data.ok) {
        setToast({ tone: "bad", text: data.error || `revert failed (${response.status})` });
        return;
      }
      closeConfirmation();
      setToast({ tone: "good", text: "returned to the config file — waiting for the gateway" });
      setTimeout(async () => {
        const now = await load();
        if (now) setDraft(structuredClone(now));
      }, 6000);
    } catch (err) {
      setToast({ tone: "bad", text: `could not reach the server: ${err.message}` });
    } finally {
      setBusy(false);
    }
  }

  if (error || !draft) {
    return <><PageHead eyebrow="Detection & enforcement" title="Protection">Configure what the gateway detects and when it can act.</PageHead><article className="card"><p className="empty">{error || "Reading gateway settings…"}</p></article></>;
  }

  return (
    <>
      <PageHead eyebrow="Detection & enforcement" title="Protection">One place to manage detectors, automatic blocking, and decision-engine policy.</PageHead>
      <div className="protection-bar">
        <ResetControl className="settings-reset" />
        <span className={source === "console" ? "pill on" : "pill"}>{source === "console" ? "Console override" : "Config file"}</span>
        <span className="protection-status">{enabledCount}/{detectors.length} detectors active</span>
        <span className="protection-status">{autoBlockCount}/{detectors.filter((detector) => detector.blockName).length} auto-blocking</span>
        <span className="grow" />
        {dirty ? <span className="unsaved">Unsaved changes</span> : null}
        <button type="button" className="act" disabled={busy || source !== "console"} onClick={() => setConfirming("revert")}>Revert</button>
        <button type="button" className="act primary" disabled={busy || !dirty} onClick={() => setConfirming("apply")}>Apply changes</button>
      </div>

      <section className="protection-overview" aria-label="Enforcement controls">
        <article className="card protection-control"><div><span className="control-kicker">Gateway reflex</span><h2>Automatic blocking</h2><p>Trusted detector matches can be blocked immediately.</p></div><Field.Toggle label="Enabled" checked={draft.block.enabled} onChange={(value) => edit("block", "enabled", value)} /></article>
        <article className="card protection-control"><div><span className="control-kicker">Decision engine</span><h2>Policy decisions</h2><p>Apply temporary blocks and throttles written by the agent.</p></div><Field.Toggle label="Enabled" checked={draft.policy.enabled} onChange={(value) => edit("policy", "enabled", value)} /></article>
      </section>

      <section className="protection-section">
        <div className="protection-section-head"><div><h2>Detectors</h2><p>Turn detection on or off. Open a card only when you need to tune it.</p></div><span>{enabledCount} active</span></div>
        <div className="detector-grid">
          <DetectorCard detector={byName.rate_limit} draft={draft} edit={edit} toggleBlock={toggleBlock} alerts={alertsFor(byName.rate_limit.signal)}><Field.Number label="Requests per minute" value={draft.rate_limit.requests_per_minute} min={1} onChange={(value) => edit("rate_limit", "requests_per_minute", value)} /><Field.Toggle label="Refuse excess requests (429)" checked={draft.rate_limit.enforce} onChange={(value) => edit("rate_limit", "enforce", value)} /></DetectorCard>
          <DetectorCard detector={byName.attack_detection} draft={draft} edit={edit} toggleBlock={toggleBlock} alerts={alertsFor(byName.attack_detection.signal)}><Field.List label="Signatures" value={draft.attack_detection.sql_patterns || []} onChange={(value) => edit("attack_detection", "sql_patterns", value)} /></DetectorCard>
          <DetectorCard detector={byName.brute_force} draft={draft} edit={edit} toggleBlock={toggleBlock} alerts={alertsFor(byName.brute_force.signal)}><Field.Number label="Consecutive failures" value={draft.brute_force.max_failures} min={1} onChange={(value) => edit("brute_force", "max_failures", value)} /><Field.Text label="Window" value={draft.brute_force.window} onChange={(value) => edit("brute_force", "window", value)} /></DetectorCard>
          <DetectorCard detector={byName.unknown_route_scanning} draft={draft} edit={edit} toggleBlock={toggleBlock} alerts={alertsFor(byName.unknown_route_scanning.signal)}><Field.Number label="Distinct paths" value={draft.unknown_route_scanning.distinct_paths} min={2} onChange={(value) => edit("unknown_route_scanning", "distinct_paths", value)} /><Field.Text label="Window" value={draft.unknown_route_scanning.window} onChange={(value) => edit("unknown_route_scanning", "window", value)} /><Field.Number label="Maximum clients" value={draft.unknown_route_scanning.max_clients} min={1} max={100000} onChange={(value) => edit("unknown_route_scanning", "max_clients", value)} /><Field.Number label="Paths per client" value={draft.unknown_route_scanning.max_paths_per_client} min={2} max={10000} onChange={(value) => edit("unknown_route_scanning", "max_paths_per_client", value)} /></DetectorCard>
          {byName.object_enumeration ? <DetectorCard detector={byName.object_enumeration} draft={draft} edit={edit} toggleBlock={toggleBlock} alerts={alertsFor(byName.object_enumeration.signal)}><p className="detector-note">Watches the endpoints in routes.object_templates. The gateway cannot see who owns an object, so this only raises a signal.</p><Field.Number label="Distinct IDs" value={draft.object_enumeration.distinct_ids} min={2} onChange={(value) => edit("object_enumeration", "distinct_ids", value)} /><Field.Text label="Window" value={draft.object_enumeration.window} onChange={(value) => edit("object_enumeration", "window", value)} /><Field.Number label="Maximum clients" value={draft.object_enumeration.max_clients} min={1} max={100000} onChange={(value) => edit("object_enumeration", "max_clients", value)} /><Field.Number label="IDs per client" value={draft.object_enumeration.max_ids_per_client} min={2} max={10000} onChange={(value) => edit("object_enumeration", "max_ids_per_client", value)} /></DetectorCard> : null}
          {byName.object_ownership ? <DetectorCard detector={byName.object_ownership} draft={draft} edit={edit} toggleBlock={toggleBlock} alerts={alertsFor(byName.object_ownership.signal)}><p className="detector-note">Refuses someone else&apos;s object on the endpoints in routes.ownership, using the caller&apos;s verified token. Endpoints and token keys are set in the gateway config.</p><Field.Toggle label="Refuse responses it cannot check" checked={draft.object_ownership.on_unverifiable !== "allow"} onChange={(value) => edit("object_ownership", "on_unverifiable", value ? "deny" : "allow")} /><Field.Number label="Largest checked response (bytes)" value={draft.object_ownership.max_body_bytes} min={1024} max={16777216} onChange={(value) => edit("object_ownership", "max_body_bytes", value)} /></DetectorCard> : null}
          <DetectorCard detector={byName.enumeration_path_traversal} draft={draft} edit={edit} toggleBlock={toggleBlock} alerts={alertsFor(byName.enumeration_path_traversal.signal)}><Field.List label="Traversal signatures" value={draft.enumeration_path_traversal.traversal_patterns || []} onChange={(value) => edit("enumeration_path_traversal", "traversal_patterns", value)} /><Field.List label="Sensitive paths" value={draft.enumeration_path_traversal.enumeration_patterns || []} onChange={(value) => edit("enumeration_path_traversal", "enumeration_patterns", value)} /></DetectorCard>
          <DetectorCard detector={byName.ip_reputation} draft={draft} edit={edit} toggleBlock={toggleBlock} alerts={alertsFor(byName.ip_reputation.signal)}><Field.Number label="Signal score" value={draft.ip_reputation.score} min={0} max={100} onChange={(value) => edit("ip_reputation", "score", value)} /><Field.Text label="Quiet period" value={draft.ip_reputation.cooldown} onChange={(value) => edit("ip_reputation", "cooldown", value)} /></DetectorCard>
        </div>
      </section>

      <section className="protection-section protection-advanced"><details className="card"><summary>Advanced enforcement settings</summary><div className="advanced-protection-grid"><Field.Number label="Minimum auto-block score" value={draft.block.min_score} min={0} max={100} onChange={(value) => edit("block", "min_score", value)} /><Field.Text label="Block duration" value={draft.block.duration} onChange={(value) => edit("block", "duration", value)} /><Field.List label="Never auto-block (CIDRs)" value={draft.block.exempt_cidrs || []} onChange={(value) => edit("block", "exempt_cidrs", value)} /><Field.Toggle label="Enable policy throttling" checked={draft.throttle.enabled} onChange={(value) => edit("throttle", "enabled", value)} /></div>{readOnly?.adaptive_rate_limit ? <ReadOnlyRateLimit settings={readOnly.adaptive_rate_limit} /> : null}</details></section>
      {confirming ? <ConfirmDialog mode={confirming} busy={busy} value={confirmText} onChange={setConfirmText} onClose={closeConfirmation} onConfirm={confirming === "apply" ? apply : revert} /> : null}
    </>
  );
}

function DetectorCard({ detector, draft, edit, toggleBlock, alerts, children }) {
  const enabled = draft[detector.section].enabled;
  const autoBlock = detector.blockName && draft.block.signals?.includes(detector.blockName);
  return <article className={enabled ? "card detector-card" : "card detector-card off"}><div className="detector-card-head"><div><h3>{detector.name}</h3><p>{detector.summary(draft)}</p></div><Field.Toggle label={enabled ? "On" : "Off"} checked={enabled} onChange={(value) => edit(detector.section, "enabled", value)} /></div><div className="detector-meta"><span>{alerts} alerts</span>{detector.blockName ? <label className="detector-block"><input type="checkbox" checked={Boolean(autoBlock)} onChange={() => toggleBlock(detector.blockName)} /> Auto-block</label> : <span className="advisory">Advisory</span>}</div><details className="detector-tuning"><summary>Tune</summary><div className="detector-fields">{children}</div></details></article>;
}

function ReadOnlyRateLimit({ settings }) {
  return <div className="readonly-rate-limit"><span>Boot-time rate-limit wiring</span><div>{settings.fallback_requests_per_minute} req/min fallback · burst {settings.burst} · Redis {settings.redis_timeout}</div></div>;
}

function ConfirmDialog({ mode, busy, value, onChange, onClose, onConfirm }) {
  return <div className="modal-overlay" onMouseDown={() => !busy && onClose()}><div className="modal-card" role="dialog" aria-modal="true" onMouseDown={(event) => event.stopPropagation()}><h2>{mode === "apply" ? "Apply protection changes?" : "Revert to config file?"}</h2><p>{mode === "apply" ? "The running gateway will update without restarting." : "This removes the console override."}</p><label className="modal-label">Type <b>{mode}</b> to confirm<input type="text" autoFocus disabled={busy} value={value} onChange={(event) => onChange(event.target.value)} onKeyDown={(event) => event.key === "Enter" && value === mode && !busy && onConfirm()} placeholder={mode} /></label><div className="modal-actions"><button type="button" className="act" disabled={busy} onClick={onClose}>Cancel</button><button type="button" className="act danger" disabled={busy || value !== mode} onClick={onConfirm}>{busy ? "Working…" : mode === "apply" ? "Apply" : "Revert"}</button></div></div></div>;
}
