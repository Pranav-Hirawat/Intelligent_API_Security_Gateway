"use client";

import { useMemo, useRef, useState } from "react";
import { ClearCampaignsControl, PageHead } from "@/app/ui/chrome";
import { CampaignsIcon } from "@/app/ui/icons";
import { CampaignCard, EmptyState, ExportMenu, IpFilterField, SegmentedControl, SnapshotButton } from "@/app/ui/parts";
import { CAMPAIGN_COLUMNS } from "@/app/ui/export";
import { useLive } from "@/app/ui/store";

const SORTS = {
  confidence: (a, b) => b.confidence - a.confidence,
  events: (a, b) => b.events - a.events,
  ips: (a, b) => b.ips.length - a.ips.length,
  newest: (a, b) => new Date(b.lastSeen) - new Date(a.lastSeen),
};

export default function CampaignsPage() {
  const { campaigns, busy, instruct } = useLive();
  const [status, setStatus] = useState("all");
  const [sort, setSort] = useState("confidence");
  const [compact, setCompact] = useState(false);
  const [selected, setSelected] = useState([]);
  const [ip, setIp] = useState("");
  const snapRef = useRef(null);

  const shown = useMemo(() => {
    let filtered =
      status === "all" ? campaigns : campaigns.filter((c) => c.status === status);
    if (ip) filtered = filtered.filter((c) => c.ips.includes(ip));
    return [...filtered].sort(SORTS[sort]);
  }, [campaigns, status, sort, ip]);

  const counts = {
    all: campaigns.length,
    active: campaigns.filter((c) => c.status === "active").length,
    contained: campaigns.filter((c) => c.status === "contained").length,
  };

  // Acting on several campaigns at once is the difference between a console
  // and a report, and it is one instruction per address either way.
  //
  // Resolved against every campaign rather than the filtered view: selecting a
  // card and then changing tab used to leave the button armed but empty, so it
  // reported success having done nothing.
  const selectedIps = campaigns
    .filter((c) => selected.includes(c.id))
    .flatMap((c) => c.ips);

  function toggle(id) {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );
  }

  return (
    <div ref={snapRef} className="page-body">
      <PageHead title="Campaigns">
        What the control plane correlated out of the raw events — rebuilt every cycle,
        and the only place an address becomes an attacker rather than a row in a log.
      </PageHead>

      <div className="toolbar">
        <SegmentedControl
          value={status}
          onChange={setStatus}
          options={["all", "active", "contained"].map((key) => ({
            value: key,
            label: key,
            count: counts[key],
          }))}
        />

        <label className="field">
          Sort
          <select value={sort} onChange={(e) => setSort(e.target.value)}>
            <option value="confidence">confidence</option>
            <option value="events">events</option>
            <option value="ips">addresses</option>
            <option value="newest">most recent</option>
          </select>
        </label>

        <label className="check">
          <input
            type="checkbox"
            checked={compact}
            onChange={(e) => setCompact(e.target.checked)}
          />
          Compact
        </label>

        <IpFilterField value={ip} onChange={setIp} placeholder="Only this IP…" />

        <span className="grow" />

        <ExportMenu rows={shown} columns={CAMPAIGN_COLUMNS} prefix="campaigns" />
        <SnapshotButton targetRef={snapRef} prefix="campaigns" title="Download a PNG of this campaigns view" />

        <ClearCampaignsControl className="act" />

        {selected.length ? (
          <div className="bulk">
            <span>
              {selected.length} selected · {selectedIps.length} addresses
            </span>
            <button
              type="button"
              className="act"
              disabled={Boolean(busy)}
              onClick={async () => {
                const ok = await instruct(selectedIps, "temp_block", "bulk");
                if (ok) setSelected([]);
              }}
            >
              {busy === "bulk:temp_block" ? "…" : "temp block all"}
            </button>
            <button type="button" className="act" onClick={() => setSelected([])}>
              clear
            </button>
          </div>
        ) : null}
      </div>

      {shown.length === 0 ? (
        <article className="card">
          {campaigns.length ? (
            <EmptyState icon={CampaignsIcon} title={`No ${status} campaigns.`} />
          ) : (
            <EmptyState
              icon={CampaignsIcon}
              title="No campaigns yet."
            />
          )}
        </article>
      ) : (
        <ul className="campaign-grid">
          {shown.map((c) => (
            <CampaignCard
              key={c.id}
              campaign={c}
              onInstruct={instruct}
              busy={busy}
              compact={compact}
              selectable
              selected={selected.includes(c.id)}
              onToggleSelect={() => toggle(c.id)}
            />
          ))}
        </ul>
      )}
    </div>
  );
}
