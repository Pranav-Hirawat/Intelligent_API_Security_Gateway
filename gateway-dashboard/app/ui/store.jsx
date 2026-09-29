"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { actionLabel } from "./format";

/**
 * One poller for the whole console.
 *
 * It lives in the layout rather than in a page, so moving between pages does
 * not restart the clock or blank the screen: the data is already there when
 * the next page renders. Pausing stops the timer everywhere at once, which is
 * the only behaviour that makes sense when the pause button is in the header.
 */
const LiveContext = createContext(null);

const EMPTY_OVERVIEW = {
  redis: false,
  stats: { requests: 0, alerts: 0, decisions: {}, signals: {} },
  attackers: [],
  events: [],
  sources: [],
  setup: [],
  site: null,
};

const EMPTY_PLANE = {
  redis: false,
  campaigns: [],
  policies: [],
  alerts: [],
  learned: [],
  heartbeat: { alive: false },
  active: 0,
};

const EMPTY_HISTORY = { available: false, campaigns: [], byType: [], total: 0 };

export function LiveProvider({ children, me }) {
  const [overview, setOverview] = useState(EMPTY_OVERVIEW);
  const [plane, setPlane] = useState(EMPTY_PLANE);
  const [history, setHistory] = useState(EMPTY_HISTORY);
  const [paused, setPaused] = useState(false);
  const [busy, setBusy] = useState("");
  // A queued override has been accepted by the console but has not yet been
  // reflected by the decision engine. It must not be mistaken for current state.
  const [pendingPolicyActions, setPendingPolicyActions] = useState({});
  const [toast, setToast] = useState(null);
  const [updatedAt, setUpdatedAt] = useState(null);
  // A page-wide flash when a NEW escalation lands, not a steady light for as
  // long as one is active -- that is what the statusbar's "N escalated"
  // count already does. null means no flash is showing; any other value is a
  // key that changes on every new escalation, so re-triggering the animation
  // does not depend on React noticing a boolean actually changed.
  const [flashEscalate, setFlashEscalate] = useState(null);
  // Alert stream ids already accounted for. A ref, not state: updating it
  // must never itself cause a render. Starts empty so the very first poll can
  // establish a baseline instead of flashing for escalations that were
  // already sitting there before the page opened.
  const seenAlertIds = useRef(null);

  const refresh = useCallback(async () => {
    try {
      // Independent reads: the gateway's telemetry and the agent's
      // conclusions. Either can be empty without the other being wrong.
      const [a, b] = await Promise.all([
        fetch("/api/overview", { cache: "no-store" }).then((r) => r.json()),
        fetch("/api/campaigns", { cache: "no-store" }).then((r) => r.json()),
      ]);
      setOverview(a);
      setPlane(b);

      // New escalations, not a resnapshot of however many are currently
      // active -- readAlerts already returns the most recent 20, so diffing
      // against last poll's ids is enough without storing history ourselves.
      const alertIds = (b.alerts || []).map((alert) => alert.id);
      if (seenAlertIds.current === null) {
        // First poll of this page load: record what already existed, flash
        // nothing. Otherwise every escalation from before the page was even
        // open would flash the moment it loads.
        seenAlertIds.current = new Set(alertIds);
      } else {
        const fresh = (b.alerts || []).filter((alert) => !seenAlertIds.current.has(alert.id));
        seenAlertIds.current = new Set(alertIds);
        if (fresh.length) {
          setFlashEscalate(fresh[0].id);
          setToast({
            tone: "bad",
            text:
              fresh.length === 1
                ? `Escalated: ${fresh[0].explanation || fresh[0].type || "campaign " + fresh[0].campaignId}`
                : `${fresh.length} campaigns escalated`,
          });
        }
      }

      setPendingPolicyActions((pending) => {
        const next = { ...pending };
        for (const [ip, action] of Object.entries(pending)) {
          if ((b.policies || []).some((policy) => policy.ip === ip && policy.action === action)) {
            delete next[ip];
          }
        }
        return next;
      });
      setUpdatedAt(new Date());
    } catch {
      setOverview((prev) => ({ ...prev, redis: false }));
    }
  }, []);

  const refreshHistory = useCallback(async () => {
    try {
      const res = await fetch("/api/history", { cache: "no-store" });
      setHistory(await res.json());
    } catch {
      /* the panel reports its own unavailability */
    }
  }, []);

  useEffect(() => {
    refresh();
    // Paused still loads once, so arriving on a page while paused shows data.
    const id = paused ? null : setInterval(refresh, 2500);
    return () => id && clearInterval(id);
  }, [paused, refresh]);

  useEffect(() => {
    refreshHistory();
    // The record only changes when a campaign does; 30s is generous.
    const id = paused ? null : setInterval(refreshHistory, 30_000);
    return () => id && clearInterval(id);
  }, [paused, refreshHistory]);

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 6000);
    return () => clearTimeout(id);
  }, [toast]);

  useEffect(() => {
    if (flashEscalate === null) return;
    // Longer than the CSS animation (1.6s) so the element is still mounted
    // while it plays, and short enough that a second escalation moments
    // later reads as a second flash rather than an extension of the first.
    const id = setTimeout(() => setFlashEscalate(null), 2000);
    return () => clearTimeout(id);
  }, [flashEscalate]);

  // Declared before instruct uses it: a dependency array is evaluated while
  // the component body runs, so a const declared further down is still in its
  // temporal dead zone.
  const canAct = me ? me.role === "operator" || me.role === "admin" : false;

  /**
   * Send the agent an instruction about some addresses.
   *
   * Never call this an enforcement path: it writes to the override stream, and
   * the agent applies it on its next cycle after the same allowlist and
   * collateral checks its own decisions face.
   */
  const instruct = useCallback(async (ips, action, label, reason) => {
    const targets = [...new Set(ips)].filter(Boolean);
    if (!targets.length) return false;

    if (!canAct) {
      setToast({
        tone: "bad",
        text: "your account can read the console but not change enforcement",
      });
      return false;
    }

    setBusy(`${label}:${action}`);
    try {
      const results = await Promise.all(
        targets.map((ip) =>
          fetch("/api/overrides", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              ip,
              action,
              actor: "dashboard",
              reason: reason || `${actionLabel(action)} set from the console`,
            }),
          }).then((r) => r.json()),
        ),
      );

      const failed = results.filter((r) => !r.ok);
      if (failed.length) {
        setToast({
          tone: "bad",
          text: `${failed.length} of ${targets.length} rejected: ${failed[0].error}`,
        });
        return false;
      }

      // The next action must be based on the state the decision engine applied,
      // not the policy row rendered before this request was queued.
      setPendingPolicyActions((pending) => ({
        ...pending,
        // Monitor intentionally writes no enforcement key, so there is no
        // policy row that can acknowledge it.
        ...(action === "monitor" ? {} : Object.fromEntries(targets.map((ip) => [ip, action]))),
      }));
      await refresh();

      setToast({
        tone: "good",
        text: `${actionLabel(action)} queued for ${targets.length} ${
          targets.length === 1 ? "address" : "addresses"
        } — applies next cycle`,
      });
      return true;
    } catch (err) {
      setToast({ tone: "bad", text: `could not reach the gateway: ${err.message}` });
      return false;
    } finally {
      setBusy("");
    }
  }, [canAct, refresh]);

  /** Remove one current policy key immediately, rather than queueing an override. */
  const deletePolicy = useCallback(async (ip) => {
    if (!canAct) {
      setToast({
        tone: "bad",
        text: "your account can read the console but not remove enforcement",
      });
      return false;
    }

    setBusy(`delete-policy:${ip}`);
    try {
      const res = await fetch(`/api/policies/${encodeURIComponent(ip)}`, { method: "DELETE" });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setToast({ tone: "bad", text: `policy delete failed: ${data.error || res.status}` });
        return false;
      }

      setToast({
        tone: "good",
        text: data.removed
          ? `policy removed for ${ip}`
          : `no current policy existed for ${ip}`,
      });
      await refresh();
      return true;
    } catch (err) {
      setToast({ tone: "bad", text: `could not reach the server: ${err.message}` });
      return false;
    } finally {
      setBusy("");
    }
  }, [canAct, refresh]);

  const value = useMemo(
    () => ({
      me,
      // Convenience only. The server checks the role on every write, so a
      // viewer who forges a request is refused there, not here.
      canAct,
      overview,
      plane,
      history,
      paused,
      setPaused,
      busy,
      pendingPolicyActions,
      toast,
      setToast,
      flashEscalate,
      updatedAt,
      instruct,
      deletePolicy,
      refresh,
      refreshHistory,
      // Read straight off the payloads so a page never has to guess a default.
      stats: overview.stats || EMPTY_OVERVIEW.stats,
      events: overview.events || [],
      sources: overview.sources || [],
      attackers: overview.attackers || [],
      setup: overview.setup || [],
      campaigns: plane.campaigns || [],
      policies: plane.policies || [],
      escalations: plane.alerts || [],
      learned: plane.learned || [],
      beat: plane.heartbeat || { alive: false },
    }),
    [
      me, canAct, overview, plane, history, paused, busy, pendingPolicyActions, toast,
      flashEscalate, updatedAt, instruct, deletePolicy, refresh, refreshHistory,
    ],
  );

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive() {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive must be used inside <LiveProvider>");
  return ctx;
}
