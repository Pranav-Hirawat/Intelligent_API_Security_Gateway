"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { useLive } from "./store";
import {
  AgentIcon,
  EscalatedIcon,
  PolicyCountIcon,
  RedisIcon,
  RefreshIcon,
} from "./icons";
import { DISPLAY_TIME_ZONE_LABEL, formatTime } from "./format";

// Text-only, no per-item icon -- the mockup's nav is plain buttons with a
// bottom-border active state, not an icon rail.
const NAV = [
  { href: "/", label: "Overview" },
  { href: "/campaigns", label: "Campaigns" },
  { href: "/policy", label: "Policy" },
  { href: "/adaptive", label: "Adaptive" },
  { href: "/events", label: "Events" },
  { href: "/history", label: "History" },
  { href: "/settings", label: "Protection" },
];

export function Shell({ children }) {
  const { overview, policies, campaigns, escalations, beat, paused, setPaused, updatedAt, toast, setToast, flashEscalate, refresh } =
    useLive();
  const pathname = usePathname();
  const [theme, setTheme] = useState("dark");
  const [spinning, setSpinning] = useState(false);

  function refreshNow() {
    refresh();
    setSpinning(true);
    setTimeout(() => setSpinning(false), 850);
  }

  useEffect(() => {
    const stored = localStorage.getItem("iasg-theme");
    const next = stored === "light" || stored === "dark" ? stored : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    localStorage.setItem("iasg-theme", next);
    document.documentElement.setAttribute("data-theme", next);
  }

  // Counts that belong on the tab itself, so you can see there is something to
  // look at without opening the page.
  const badges = {
    "/campaigns": campaigns.filter((c) => c.status === "active").length,
    "/policy": policies.length,
  };

  return (
    <>
      <header className="top">
        <div className="brand">
          <span className="logo">
            <span className="logo-dot" />
          </span>
          <div className="brand-text">
            IASG<span className="brand-sub"> Operations</span>
          </div>
        </div>

        <nav className="nav">
          {NAV.map((item) => {
            const active =
              item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={active ? "nav-link active" : "nav-link"}
              >
                {item.label}
                {badges[item.href] ? <em>{badges[item.href]}</em> : null}
              </Link>
            );
          })}
        </nav>

        <div className="header-tools">
          <div className="live-group">
            <button
              type="button"
              onClick={() => setPaused((p) => !p)}
              title="Stop the 2.5s refresh while you read"
            >
              <span className={paused ? "live-dot" : "live-dot on"} />
              <span className="live-label">{paused ? "Paused" : "Live"}</span>
            </button>
            <button
              type="button"
              className={spinning ? "refresh-btn spinning" : "refresh-btn"}
              onClick={refreshNow}
              title="Refresh now"
              aria-label="Refresh now"
            >
              <RefreshIcon size={13} aria-hidden="true" />
            </button>
          </div>

          <div className="refreshed-label">
            {paused ? "Paused" : updatedAt ? `Updated ${formatTime(updatedAt)} ${DISPLAY_TIME_ZONE_LABEL}` : "Connecting"}
          </div>

          {overview.site?.city ? (
            <div className="host-label mono">
              {overview.site.city}
              {overview.site.country ? ` · ${overview.site.country}` : ""}
            </div>
          ) : null}

          <button
            type="button"
            className="theme-btn"
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light" : "Switch to dark"}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            {theme === "dark" ? "Light" : "Dark"}
          </button>
        </div>
      </header>

      <div className="statusbar">
        <div className="statusbar-inner">
          <RedisIcon size={13} aria-hidden="true" />
          <span className={`dot ${overview.redis ? "on" : "off"}`} />
          {overview.redis ? "Redis connected" : "Redis unavailable"}
          <span className="sep" />
          {/* Liveness, not activity. A quiet network and a dead agent look
              identical without this, and they mean opposite things. */}
          <AgentIcon size={13} aria-hidden="true" />
          <span className={`dot ${beat.alive ? (beat.late ? "late" : "on") : "off"}`} />
          {beat.alive
            ? beat.late
              ? `Agent late — ${beat.secondsAgo}s since last cycle`
              : `Agent live — cycled ${beat.secondsAgo}s ago`
            : "Agent not running"}
          {beat.alive && beat.dryRun ? " (dry run)" : ""}
          {beat.alive && beat.durable ? (
            <>
              <span className="sep" />
              Durable
            </>
          ) : null}
          {beat.alive && beat.narrationProvider === "ollama" ? (
            <>
              <span className="sep" />
              <span title="The explanation and assessment agents are writing with a local model instead of the offline template.">
                Narration: Ollama
              </span>
            </>
          ) : null}
          <span className="sep" />
          <PolicyCountIcon size={13} aria-hidden="true" />
          {policies.length > 0
            ? `${policies.length} policy ${policies.length === 1 ? "key" : "keys"} in force`
            : "Detect-only"}
          {escalations.length ? (
            <>
              <span className="sep" />
              <Link href="/policy" className="risk high">
                <EscalatedIcon size={13} aria-hidden="true" />
                {escalations.length} escalated
              </Link>
            </>
          ) : null}
          <span className="grow" />
          <span className="mono">
            {paused ? "Paused" : updatedAt ? `Refreshed ${formatTime(updatedAt)} ${DISPLAY_TIME_ZONE_LABEL}` : "Connecting"}
          </span>
        </div>
      </div>

      {toast ? (
        <div className={`toast ${toast.tone}`} role="status">
          {toast.text}
          <button type="button" onClick={() => setToast(null)} aria-label="Dismiss">
            ×
          </button>
        </div>
      ) : null}

      {flashEscalate !== null ? (
        // Keyed so a second escalation while the first flash is still fading
        // remounts the element and restarts the animation, rather than
        // reusing a node CSS thinks is already mid-animation.
        <div key={flashEscalate} className="escalate-flash" aria-hidden="true" />
      ) : null}

      <main className="app">{children}</main>
    </>
  );
}

/**
 * Reset the console to a clean slate.
 *
 * Destructive, so it is two steps: a Settings-page control that opens a
 * dialog, and a dialog that will not act until you type the word the server
 * also demands.
 * On success it refreshes the live data, so the console visibly empties rather
 * than waiting for the next poll.
 */
export function ResetControl({ className = "icon-btn", label = "Reset console" }) {
  const { refresh, refreshHistory, setToast } = useLive();
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [dialogVersion, setDialogVersion] = useState(0);

  useEffect(() => {
    if (!open) return undefined;
    function escape(event) {
      if (event.key === "Escape" && !busy) close();
    }
    document.addEventListener("keydown", escape);
    return () => document.removeEventListener("keydown", escape);
  }, [open, busy]);

  function openDialog() {
    // Clears whatever a previous run left behind, so a dialog that somehow
    // got here still busy (see run(), below) starts clean rather than
    // reopening pre-disabled -- the "doesn't take input" report was this
    // exact state, left by the request-scoped guard against it added there.
    setBusy(false);
    setConfirm("");
    // Reset owns its dialog state. Forcing a fresh modal instance prevents a
    // stale focused/disabled input from a completed policy mutation surviving
    // the route change into this unrelated action.
    setDialogVersion((version) => version + 1);
    setOpen(true);
  }

  function close() {
    // A fresh dialog must never inherit a disabled state from a request that
    // completed after the previous dialog closed.
    setBusy(false);
    setOpen(false);
    setConfirm("");
  }

  async function run() {
    setBusy(true);
    try {
      // A reset that outlives the dialog is fine; a reset the dialog can
      // never come back from is the bug. Bounded so a slow or wedged
      // Postgres/Redis cannot pin this request open indefinitely.
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15_000);
      let res;
      try {
        res = await fetch("/api/admin/reset", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ confirm: "reset" }),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeout);
      }
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setToast({ tone: "bad", text: `reset failed: ${data.error || res.status}` });
        return;
      }
      const pg = data.postgres?.ok
        ? Object.values(data.postgres.cleared || {}).reduce((a, b) => a + b, 0)
        : 0;
      const keys = data.redis?.ok ? data.redis.removed : 0;
      const events = data.redis?.ok ? data.redis.trimmed : 0;
      setToast({
        tone: "good",
        text: `console reset — cleared ${pg} campaign record(s), ${events} event(s) and ${keys} live key(s)`,
      });
      close();
      // The live panels read Redis, but History reads Postgres on its own
      // slower cadence. Refresh both lanes now so a successful reset does not
      // leave deleted campaigns visible until the next 30-second history poll
      // -- fire-and-forget, not awaited: reopening this dialog right after a
      // reset must not find it still "busy" from a refresh that is slow or
      // never returns. Either read reports its own failure already.
      refresh();
      refreshHistory();
    } catch (err) {
      setToast({
        tone: "bad",
        text: err.name === "AbortError"
          ? "reset timed out waiting for the server"
          : `could not reach the server: ${err.message}`,
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        className={className}
        onClick={openDialog}
        title="Reset the console to a clean slate"
      >
        {label}
      </button>

      {open && typeof document !== "undefined"
        ? createPortal(
        <div key={dialogVersion} className="modal-overlay" onMouseDown={() => !busy && close()}>
          <div
            className="modal-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="reset-dialog-title"
            onMouseDown={(e) => e.stopPropagation()}
          >
            <h2 id="reset-dialog-title">Reset the console?</h2>
            <p>
              This clears the campaign history in Postgres and the live telemetry
              in Redis — Overview, Events, Campaigns and History all go back to
              empty.
            </p>
            <p className="modal-note">
              To lift a current policy key, use Delete policy on the Policy page.
            </p>
            <p className="modal-note">
              Active policy blocks are left running; they expire on their own.
              This cannot be undone.
            </p>
            <label className="modal-label">
              Type <b>reset</b> to confirm
              <input
                type="text"
                value={confirm}
                autoFocus
                disabled={busy}
                onChange={(e) => setConfirm(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && confirm === "reset" && !busy) run();
                }}
                placeholder="reset"
              />
            </label>
            <div className="modal-actions">
              <button type="button" className="act" onClick={close} disabled={busy}>
                Cancel
              </button>
              <button
                type="button"
                className="act danger"
                onClick={run}
                disabled={busy || confirm !== "reset"}
              >
                {busy ? "Resetting…" : "Reset console"}
              </button>
            </div>
          </div>
        </div>,
        document.body,
      )
        : null}
    </>
  );
}

/**
 * Clear campaigns -- narrower than Reset console above: only the agent's
 * groupings (campaigns + the feedback learned from them), never raw events
 * and never active policy. See app/api/admin/clear-campaigns for exactly
 * what is and is not touched, and why clearing here can't be undone by
 * whatever evidence the control plane was mid-cycle on when this runs.
 */
export function ClearCampaignsControl({ className = "icon-btn", label = "Clear campaigns" }) {
  const { refresh, refreshHistory, setToast } = useLive();
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return undefined;
    function escape(event) {
      if (event.key === "Escape" && !busy) close();
    }
    document.addEventListener("keydown", escape);
    return () => document.removeEventListener("keydown", escape);
  }, [open, busy]);

  function openDialog() {
    // See ResetControl's openDialog: clears a stuck busy flag left by a
    // previous run() rather than reopening the dialog pre-disabled.
    setBusy(false);
    setConfirm("");
    setOpen(true);
  }

  function close() {
    setOpen(false);
    setConfirm("");
  }

  async function run() {
    setBusy(true);
    try {
      // Bounded so a slow or wedged Postgres cannot pin this request open
      // indefinitely -- see ResetControl's run() for the same guard.
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15_000);
      let res;
      try {
        res = await fetch("/api/admin/clear-campaigns", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ confirm: "clear" }),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeout);
      }
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setToast({ tone: "bad", text: `clear failed: ${data.error || res.status}` });
        return;
      }
      setToast({
        tone: "good",
        text:
          `cleared ${data.cleared} record(s) — ${data.campaigns} campaign(s), ` +
          `${data.feedback} feedback entr${data.feedback === 1 ? "y" : "ies"}. ` +
          "Events and active policy are untouched.",
      });
      close();
      // History reads Postgres on its own slower cadence -- refresh both
      // lanes now so this doesn't leave cleared campaigns visible until the
      // next 30-second history poll. Fire-and-forget: reopening this dialog
      // right after clearing must not find it still "busy" from a refresh
      // that is slow or never returns. Either read reports its own failure.
      refresh();
      refreshHistory();
    } catch (err) {
      setToast({
        tone: "bad",
        text: err.name === "AbortError"
          ? "clear timed out waiting for the server"
          : `could not reach the server: ${err.message}`,
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        className={className}
        onClick={openDialog}
        disabled={busy}
        title="Clear campaigns -- keeps raw events and active policy"
      >
        {label}
      </button>

      {open && typeof document !== "undefined"
        ? createPortal(
        <div className="modal-overlay" onMouseDown={() => !busy && close()}>
          <div
            className="modal-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="clear-campaigns-dialog-title"
            onMouseDown={(e) => e.stopPropagation()}
          >
            <h2 id="clear-campaigns-dialog-title">Clear campaigns?</h2>
            <p>
              Deletes every campaign and the feedback learned from them, in Postgres
              and Redis. Campaigns rebuild from new evidence as the control plane
              keeps running.
            </p>
            <p className="modal-note">
              Raw events on the Events page and active policy on the Policy page are
              not touched. A policy that named a cleared campaign keeps enforcing;
              its campaign link just won't resolve to anything anymore.
            </p>
            <p className="modal-note">This cannot be undone.</p>
            <label className="modal-label">
              Type <b>clear</b> to confirm
              <input
                type="text"
                value={confirm}
                autoFocus
                disabled={busy}
                onChange={(e) => setConfirm(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && confirm === "clear" && !busy) run();
                }}
                placeholder="clear"
              />
            </label>
            <div className="modal-actions">
              <button type="button" className="act" onClick={close} disabled={busy}>
                Cancel
              </button>
              <button
                type="button"
                className="act danger"
                onClick={run}
                disabled={busy || confirm !== "clear"}
              >
                {busy ? "Clearing…" : "Clear campaigns"}
              </button>
            </div>
          </div>
        </div>,
        document.body,
      )
        : null}
    </>
  );
}

export function PageHead({ title, eyebrow, actions, children }) {
  return (
    <div className="page-head">
      <div className="page-head-row">
        <div>
          {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
          <h1>{title}</h1>
          <p>{children}</p>
        </div>
        {actions ? <div className="page-head-actions">{actions}</div> : null}
      </div>
    </div>
  );
}
