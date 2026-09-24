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
 * A destructive admin action in two steps: a button that opens a dialog, and a
 * dialog that will not act until you type the word the server also demands.
 * On success it refreshes the live data, so the console visibly empties rather
 * than waiting for the next poll. Reset and Clear campaigns differ only in
 * what they say and which endpoint they call, so they share this.
 */
function TypedConfirmControl({
  className, label, word, endpoint, dialogId, heading, body, triggerTitle,
  confirmLabel, busyLabel, disableTriggerWhileBusy, successText,
}) {
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
    // Clears whatever a previous run left behind, so a dialog that somehow
    // got here still busy (see run(), below) starts clean rather than
    // reopening pre-disabled -- the "doesn't take input" report was this
    // exact state, left by the request-scoped guard against it added there.
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
      // An action that outlives the dialog is fine; one the dialog can never
      // come back from is the bug. Bounded so a slow or wedged Postgres/Redis
      // cannot pin this request open indefinitely.
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15_000);
      let res;
      try {
        res = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ confirm: word }),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeout);
      }
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setToast({ tone: "bad", text: `${word} failed: ${data.error || res.status}` });
        return;
      }
      setToast({ tone: "good", text: successText(data) });
      close();
      // The live panels read Redis, but History reads Postgres on its own
      // slower cadence. Refresh both lanes now so a success does not leave
      // deleted campaigns visible until the next 30-second history poll --
      // fire-and-forget, not awaited: reopening this dialog right after must
      // not find it still "busy" from a refresh that is slow or never
      // returns. Either read reports its own failure already.
      refresh();
      refreshHistory();
    } catch (err) {
      setToast({
        tone: "bad",
        text: err.name === "AbortError"
          ? `${word} timed out waiting for the server`
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
        disabled={disableTriggerWhileBusy ? busy : undefined}
        title={triggerTitle}
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
            aria-labelledby={dialogId}
            onMouseDown={(e) => e.stopPropagation()}
          >
            <h2 id={dialogId}>{heading}</h2>
            {body}
            <label className="modal-label">
              Type <b>{word}</b> to confirm
              <input
                type="text"
                value={confirm}
                autoFocus
                disabled={busy}
                onChange={(e) => setConfirm(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && confirm === word && !busy) run();
                }}
                placeholder={word}
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
                disabled={busy || confirm !== word}
              >
                {busy ? busyLabel : confirmLabel}
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

/** Reset the console to a clean slate. */
export function ResetControl({ className = "icon-btn", label = "Reset console" }) {
  return (
    <TypedConfirmControl
      className={className}
      label={label}
      word="reset"
      endpoint="/api/admin/reset"
      dialogId="reset-dialog-title"
      heading="Reset the console?"
      triggerTitle="Reset the console to a clean slate"
      confirmLabel="Reset console"
      busyLabel="Resetting…"
      body={
        <>
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
        </>
      }
      successText={(data) => {
        const pg = data.postgres?.ok
          ? Object.values(data.postgres.cleared || {}).reduce((a, b) => a + b, 0)
          : 0;
        const keys = data.redis?.ok ? data.redis.removed : 0;
        const events = data.redis?.ok ? data.redis.trimmed : 0;
        return `console reset — cleared ${pg} campaign record(s), ${events} event(s) and ${keys} live key(s)`;
      }}
    />
  );
}

/**
 * Clear campaigns -- narrower than Reset console: only the agent's groupings
 * (campaigns + the feedback learned from them), never raw events and never
 * active policy. See app/api/admin/clear-campaigns for exactly what is and is
 * not touched, and why clearing here can't be undone by whatever evidence the
 * control plane was mid-cycle on when this runs.
 */
export function ClearCampaignsControl({ className = "icon-btn", label = "Clear campaigns" }) {
  return (
    <TypedConfirmControl
      className={className}
      label={label}
      word="clear"
      endpoint="/api/admin/clear-campaigns"
      dialogId="clear-campaigns-dialog-title"
      heading="Clear campaigns?"
      triggerTitle="Clear campaigns -- keeps raw events and active policy"
      confirmLabel="Clear campaigns"
      busyLabel="Clearing…"
      disableTriggerWhileBusy
      body={
        <>
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
        </>
      }
      successText={(data) =>
        `cleared ${data.cleared} record(s) — ${data.campaigns} campaign(s), ` +
        `${data.feedback} feedback entr${data.feedback === 1 ? "y" : "ies"}. ` +
        "Events and active policy are untouched."}
    />
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
