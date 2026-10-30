import { useContext, useMemo, useState, type ReactNode } from "react";
import { ChevronDown, ChevronRight, Monitor, Search, Wifi } from "lucide-react";
import { WorkContext } from "../context";
import { useData } from "../hooks/useData";
import { useT } from "../i18n";
import { HelpButton } from "../components/Help";

type Ap = {
  id: string;
  name: string;
  kind: string;
  status: string;
  last_seen: string | null;
  controller_id: string | null;
  groups: string[];
  fresh: boolean;
  clients_total: number;
  registered_now: string[];
  unregistered_now: number;
  previously_seen: string[];
  model?: string;
  version?: string;
};
type Computer = {
  id: string;
  hostname: string;
  mac: string;
  owner: string | null;
  rank: string | null;
  groups: string[];
  wifi: "ASSOCIATED" | "NOT_ASSOCIATED" | "UNKNOWN";
  ap_id: string | null;
  last_ap_id: string | null;
  signal: string | null;
  wifi_observed_at: string | null;
  agent: "ONLINE" | "STALE" | "NEVER";
  last_heartbeat: string | null;
  compliance: string;
  score: number | null;
  awaiting_enforcement: boolean;
  failed_operations: number;
  never_seen: boolean;
};
type Explorer = {
  ap_groups: { id: string; name: string }[];
  device_groups: { id: string; name: string }[];
  access_points: Ap[];
  devices: Computer[];
  counts: Record<string, number>;
};

// Each filter tests one independent status; see backend/app/services/explorer.py for the sources.
const FILTERS: Record<string, (d: Computer) => boolean> = {
  registered: () => true,
  wifi_associated: (d) => d.wifi === "ASSOCIATED",
  agent_online: (d) => d.agent === "ONLINE",
  agent_offline: (d) => d.agent !== "ONLINE",
  compliant: (d) => d.compliance === "COMPLIANT",
  noncompliant: (d) => d.compliance === "NONCOMPLIANT",
  awaiting_enforcement: (d) => d.awaiting_enforcement,
  failed_operations: (d) => d.failed_operations > 0,
  offline: (d) => !d.never_seen && d.agent !== "ONLINE" && d.wifi !== "ASSOCIATED",
  never_seen: (d) => d.never_seen,
  ungrouped: (d) => !d.groups.length,
};
const BUCKETS: [string, (d: Computer) => boolean][] = [
  ["wifi", (d) => d.wifi === "ASSOCIATED"],
  ["agent_only", (d) => d.wifi !== "ASSOCIATED" && d.agent === "ONLINE"],
  ["offline", FILTERS.offline],
  ["never_seen", FILTERS.never_seen],
  ["ungrouped", FILTERS.ungrouped],
];

function time(value: string | null, language: string) {
  return value
    ? new Date(value.endsWith("Z") ? value : value + "Z").toLocaleString(
        language === "hy" ? "hy-AM" : language === "ru" ? "ru-RU" : "en-GB",
        { dateStyle: "medium", timeStyle: "short" },
      )
    : "—";
}

function StatusChips({ d }: { d: Computer }) {
  const t = useT();
  const wifi = { ASSOCIATED: "online", NOT_ASSOCIATED: "pending", UNKNOWN: "" }[d.wifi];
  const agent = { ONLINE: "online", STALE: "pending", NEVER: "" }[d.agent];
  return (
    <span className="chips">
      {d.never_seen ? (
        <span className="badge unknown">{t("count.never_seen")}</span>
      ) : (
        <>
          <span className={"badge " + wifi}>{t("wifiState." + d.wifi)}</span>
          <span className={"badge " + agent}>{t("agentState." + d.agent)}</span>
        </>
      )}
      <span className={"badge " + d.compliance.toLowerCase()}>{t(d.compliance)}</span>
      {d.failed_operations > 0 && (
        <span className="badge failed">
          {t("count.failed_operations")}: {d.failed_operations}
        </span>
      )}
    </span>
  );
}

function Branch({
  id,
  label,
  extra,
  open,
  toggle,
  level,
  children,
}: {
  id: string;
  label: ReactNode;
  extra?: ReactNode;
  open: Set<string>;
  toggle: (id: string) => void;
  level: number;
  children: () => ReactNode;
}) {
  const expanded = open.has(id);
  return (
    <li role="treeitem" aria-expanded={expanded} aria-level={level}>
      <button className="tree-row" onClick={() => toggle(id)}>
        {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        <span className="tree-label">{label}</span>
        {extra}
      </button>
      {/* Children render only when expanded, so large networks stay fast. */}
      {expanded && <ul role="group">{children()}</ul>}
    </li>
  );
}

export function NetworkExplorer() {
  const t = useT();
  const { revision } = useContext(WorkContext);
  const language = document.documentElement.lang || "hy";
  const { data, error } = useData<Explorer>("/network/explorer", revision);
  const [query, setQuery] = useState(""),
    [filter, setFilter] = useState("registered"),
    [apGroup, setApGroup] = useState(""),
    [deviceGroup, setDeviceGroup] = useState(""),
    [open, setOpen] = useState(() => new Set(["root", "computers"])),
    [selected, setSelected] = useState<{ kind: "ap" | "device"; id: string } | null>(null);
  const index = useMemo(() => {
    const devices = new Map((data?.devices || []).map((d) => [d.id, d]));
    const aps = new Map((data?.access_points || []).map((a) => [a.id, a]));
    const groupNames = new Map(
      [...(data?.ap_groups || []), ...(data?.device_groups || [])].map((g) => [g.id, g.name]),
    );
    return { devices, aps, groupNames };
  }, [data]);
  if (!data) return error ? <div className="error">{t(error)}</div> : <div className="empty">{t("loading")}</div>;
  const toggle = (id: string) =>
    setOpen((current) => {
      const next = new Set(current);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  const needle = query.trim().toLowerCase();
  const visible = (d: Computer) =>
    FILTERS[filter](d) &&
    (!deviceGroup || d.groups.includes(deviceGroup)) &&
    (!needle || [d.hostname, d.owner, d.mac].some((v) => v?.toLowerCase().includes(needle)));
  const aps = data.access_points.filter((a) => !apGroup || a.groups.includes(apGroup));
  const deviceRow = (id: string, level: number) => {
    const d = index.devices.get(id);
    if (!d || !visible(d)) return null;
    return (
      <li key={id} role="treeitem" aria-level={level} aria-selected={selected?.id === id}>
        <button
          className={"tree-row leaf" + (selected?.id === id ? " selected" : "")}
          onClick={() => setSelected({ kind: "device", id })}
        >
          <Monitor size={16} />
          <span className="tree-label">
            {d.hostname}
            {d.owner && <small>{d.owner}</small>}
          </span>
          <StatusChips d={d} />
        </button>
      </li>
    );
  };
  const apNode = (a: Ap, level: number) => (
    <Branch
      key={a.id}
      id={"ap:" + a.id}
      level={level}
      open={open}
      toggle={(id) => {
        toggle(id);
        setSelected({ kind: "ap", id: a.id });
      }}
      label={
        <>
          <Wifi size={16} /> {a.name} <small>{t("kind." + a.kind)}</small>
        </>
      }
      extra={
        <span className="chips">
          <span className={"badge " + a.status.toLowerCase()}>{t(a.status)}</span>
          <span className="count-tag">
            {a.fresh
              ? `${a.clients_total} ${t("connectedShort")} · ${a.registered_now.length} ${t("registeredShort")}`
              : t("wifiState.UNKNOWN")}
          </span>
        </span>
      }
    >
      {() => (
        <>
          {a.registered_now.map((id) => deviceRow(id, level + 1))}
          {a.previously_seen.length > 0 && (
            <Branch
              id={"prev:" + a.id}
              level={level + 1}
              open={open}
              toggle={toggle}
              label={t("previouslySeen")}
              extra={<span className="count-tag">{a.previously_seen.length}</span>}
            >
              {() => a.previously_seen.map((id) => deviceRow(id, level + 2))}
            </Branch>
          )}
        </>
      )}
    </Branch>
  );
  const ungrouped = aps.filter((a) => !a.groups.length && !a.controller_id);
  const capsByController = (id: string) => aps.filter((a) => a.controller_id === id);
  return (
    <div className="explorer">
      <p className="page-intro">{t("explorerIntro")}</p>
      <div className="explorer-counts" role="group" aria-label={t("explorerFilters")}>
        {Object.keys(FILTERS).map((key) => (
          <button
            key={key}
            className={"count-chip" + (filter === key ? " active" : "")}
            aria-pressed={filter === key}
            onClick={() => setFilter(key)}
          >
            <strong>{data.counts[key]}</strong>
            <span>{t("count." + key)}</span>
          </button>
        ))}
      </div>
      <div className="toolbar explorer-toolbar">
        <label className="search">
          <Search size={16} />
          <input
            type="search"
            value={query}
            placeholder={t("searchExplorer")}
            aria-label={t("searchExplorer")}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
        <select value={apGroup} aria-label={t("ap-groups")} onChange={(e) => setApGroup(e.target.value)}>
          <option value="">{t("allApGroups")}</option>
          {data.ap_groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
        <select value={deviceGroup} aria-label={t("device-groups")} onChange={(e) => setDeviceGroup(e.target.value)}>
          <option value="">{t("allDeviceGroups")}</option>
          {data.device_groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
        <HelpButton id="network-explorer" />
      </div>
      <div className="explorer-layout">
        <section className="card explorer-tree">
          {needle ? (
            <ul role="tree" aria-label={t("searchResults")}>
              {aps
                .filter((a) => a.name.toLowerCase().includes(needle))
                .map((a) => apNode(a, 1))}
              {data.devices.filter(visible).map((d) => deviceRow(d.id, 1))}
            </ul>
          ) : (
            <ul role="tree" aria-label={t("explorer")}>
              <Branch id="root" level={1} open={open} toggle={toggle} label={<b>{t("suroNetwork")}</b>}>
                {() => (
                  <>
                    {data.ap_groups
                      .filter((g) => !apGroup || g.id === apGroup)
                      .map((g) => {
                        const members = aps.filter((a) => a.groups.includes(g.id));
                        return (
                          <Branch
                            key={g.id}
                            id={"group:" + g.id}
                            level={2}
                            open={open}
                            toggle={toggle}
                            label={g.name}
                            extra={<span className="count-tag">{members.length}</span>}
                          >
                            {() => members.map((a) => apNode(a, 3))}
                          </Branch>
                        );
                      })}
                    {ungrouped.length > 0 && (
                      <Branch
                        id="ungrouped-aps"
                        level={2}
                        open={open}
                        toggle={toggle}
                        label={t("ungroupedAps")}
                        extra={<span className="count-tag">{ungrouped.length}</span>}
                      >
                        {() =>
                          ungrouped.map((a) =>
                            a.kind === "controller" ? (
                              <Branch
                                key={a.id}
                                id={"controller:" + a.id}
                                level={3}
                                open={open}
                                toggle={toggle}
                                label={
                                  <>
                                    <Wifi size={16} /> {a.name} <small>{t("kind.controller")}</small>
                                  </>
                                }
                                extra={<span className="count-tag">{capsByController(a.id).length}</span>}
                              >
                                {() => capsByController(a.id).map((cap) => apNode(cap, 4))}
                              </Branch>
                            ) : (
                              apNode(a, 3)
                            ),
                          )
                        }
                      </Branch>
                    )}
                    <Branch
                      id="computers"
                      level={2}
                      open={open}
                      toggle={toggle}
                      label={<b>{t("registeredComputers")}</b>}
                      extra={<span className="count-tag">{data.devices.filter(visible).length}</span>}
                    >
                      {() =>
                        BUCKETS.map(([key, test]) => {
                          const rows = data.devices.filter((d) => test(d) && visible(d));
                          return (
                            <Branch
                              key={key}
                              id={"bucket:" + key}
                              level={3}
                              open={open}
                              toggle={toggle}
                              label={t("bucket." + key)}
                              extra={<span className="count-tag">{rows.length}</span>}
                            >
                              {() => rows.map((d) => deviceRow(d.id, 4))}
                            </Branch>
                          );
                        })
                      }
                    </Branch>
                  </>
                )}
              </Branch>
            </ul>
          )}
        </section>
        <aside className="card explorer-details" aria-live="polite">
          <Details selected={selected} index={index} language={language} onSelect={setSelected} />
        </aside>
      </div>
      <details className="notice explorer-sources">
        <summary>{t("evidenceSources")}</summary>
        <ul className="plain-list">
          {["registered", "wifi", "agent", "compliance"].map((k) => (
            <li key={k}>{t("sourceNote." + k)}</li>
          ))}
        </ul>
      </details>
    </div>
  );
}

function Details({
  selected,
  index,
  language,
  onSelect,
}: {
  selected: { kind: "ap" | "device"; id: string } | null;
  index: { devices: Map<string, Computer>; aps: Map<string, Ap>; groupNames: Map<string, string> };
  language: string;
  onSelect: (value: { kind: "ap" | "device"; id: string }) => void;
}) {
  const t = useT();
  const grid = (rows: [string, ReactNode][]) => (
    <div className="detail-grid">
      {rows.map(([k, v]) => (
        <div key={k}>
          <span>{t(k)}</span>
          <strong>{v || "—"}</strong>
        </div>
      ))}
    </div>
  );
  const groups = (ids: string[]) => ids.map((id) => index.groupNames.get(id)).filter(Boolean).join(", ");
  if (selected?.kind === "ap") {
    const a = index.aps.get(selected.id);
    if (!a) return null;
    return (
      <div className="detail-content">
        <h2>{a.name}</h2>
        <p>{t("kind." + a.kind)}</p>
        {grid([
          ["status", t(a.status)],
          ["lastSuccessfulCheck", time(a.last_seen, language)],
          ["model", a.model],
          ["version", a.version],
          ["ap-groups", groups(a.groups)],
          ["connectedShort", a.fresh ? String(a.clients_total) : t("wifiState.UNKNOWN")],
          ["registeredShort", String(a.registered_now.length)],
          ["unregisteredShort", String(a.unregistered_now)],
        ])}
        <a className="button primary" href={"#access-points/" + a.id}>
          {t("openAccessPoint")}
        </a>
        {[...a.registered_now, ...a.previously_seen].length > 0 && (
          <ul className="plain-list detail-list">
            {[...a.registered_now, ...a.previously_seen].map((id) => {
              const d = index.devices.get(id);
              return d ? (
                <li key={id}>
                  <button className="link-button" onClick={() => onSelect({ kind: "device", id })}>
                    {d.hostname}
                  </button>{" "}
                  <StatusChips d={d} />
                </li>
              ) : null;
            })}
          </ul>
        )}
      </div>
    );
  }
  if (selected?.kind === "device") {
    const d = index.devices.get(selected.id);
    if (!d) return null;
    const ap = index.aps.get(d.ap_id || d.last_ap_id || "");
    return (
      <div className="detail-content">
        <h2>{d.hostname}</h2>
        <StatusChips d={d} />
        {grid([
          ["owner", [d.rank, d.owner].filter(Boolean).join(" ")],
          ["mac", <span className="mono">{d.mac}</span>],
          ["device-groups", groups(d.groups)],
          [d.ap_id ? "currentAp" : "lastKnownAp", ap?.name],
          ["signal", d.signal],
          ["wifiObservedAt", time(d.wifi_observed_at, language)],
          ["lastSeen", time(d.last_heartbeat, language)],
          ["compliance", d.score === null ? t(d.compliance) : `${t(d.compliance)} · ${d.score}%`],
        ])}
        <div className="button-row">
          <a className="button primary" href={"#devices/" + d.id}>
            {t("openComputer")}
          </a>
          {ap && (
            <button className="button secondary" onClick={() => onSelect({ kind: "ap", id: ap.id })}>
              {t("openAccessPoint")}: {ap.name}
            </button>
          )}
        </div>
      </div>
    );
  }
  return <p className="detail-content muted">{t("selectNodeHint")}</p>;
}
