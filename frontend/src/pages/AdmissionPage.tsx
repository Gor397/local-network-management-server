import { useContext, useState } from "react";
import { AlertTriangle, Search, ShieldCheck } from "lucide-react";
import { api } from "../api/client";
import { WorkContext } from "../context";
import { useData } from "../hooks/useData";
import { useT } from "../i18n";
import { HelpButton } from "../components/Help";

// Requested changes and router-confirmed state are always shown apart; see services/admission_gate.py.
type Subnet = {
  id: string;
  router_id: string;
  router_name: string | null;
  cidr: string;
  state: string;
  error: string | null;
  members: number;
  granted: number;
  rollback_commands: string[];
};
type Exempted = { device_id: string; hostname: string; mac: string; device_class: string; reason: string | null };
type Row = {
  device_id: string;
  hostname: string;
  mac: string;
  device_class: string;
  exempt: boolean;
  exemption_reason: string | null;
  client: string;
  agent: string;
  agent_version: string | null;
  last_heartbeat: string | null;
  registered_at: string | null;
  enrollment_id: string | null;
  user: null | { first_name: string | null; last_name: string | null; full_name: string; military_rank: string | null; verified: boolean };
  required: boolean;
  desired: string;
  reason: string;
  network: string;
  gate_state: string | null;
  applied: string | null;
  granted_ip: string | null;
  grant_expires_at: string | null;
  reported_ip: string | null;
  error: string | null;
  override: string | null;
  override_until: string | null;
  onboarding_until: string | null;
  connected_ap: string | null;
  source?: string | null;
  rollback_commands?: string[];
  logs?: { at: string; action: string; actor: string; details: any }[];
};
const TONE: Record<string, string> = {
  AUTHORIZED: "online", ENROLLED: "online", CONNECTED: "online", EXEMPT: "verified",
  RESTRICTED: "failed", ERROR: "failed", NOT_ENROLLED: "failed", NEVER: "failed", UNHEALTHY: "failed",
  AUTHORIZATION_PENDING: "pending", REVOCATION_PENDING: "pending", ENROLLMENT_PENDING: "pending", DISCONNECTED: "pending",
  PREPARING: "pending", PREVIEW: "pending", INSTALLED: "online", REMOVING: "pending", NOT_INSTALLED: "",
};
function useRouterOptions(revision: number) {
  const routers = useData<any[]>("/mikrotik/routers", revision);
  // Controller-managed CAPs are observed only; gates go on routers that route the computers' subnets.
  return (routers.data || []).filter((r) => !r.controller_id && !r.archived).map((r) => ({ value: r.id, label: r.name }));
}
function when(value: string | null) {
  return value ? new Date(value.endsWith("Z") ? value : value + "Z").toLocaleString() : "—";
}
function Badge({ value, prefix }: { value: string | null; prefix: string }) {
  const t = useT();
  return value ? <span className={"badge " + (TONE[value] || "")}>{t(prefix + value)}</span> : <span>—</span>;
}

export function AdmissionPage() {
  const t = useT();
  const { revision } = useContext(WorkContext);
  const [query, setQuery] = useState(""),
    [selected, setSelected] = useState<string | null>(null),
    [checked, setChecked] = useState<string[]>([]),
    [onlyRequired, setOnlyRequired] = useState(false);
  const { modal } = useContext(WorkContext);
  const options = useRouterOptions(revision);
  const toggle = (id: string) => setChecked(checked.includes(id) ? checked.filter((c) => c !== id) : [...checked, id]);
  const { data, error } = useData<{ policy: any; counts: Record<string, number>; items: Row[]; subnets?: Subnet[]; exceptions?: Exempted[] }>(
    `/admission/overview?q=${encodeURIComponent(query)}&only_required=${onlyRequired}`,
    revision,
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>
            {t("adm.title")} <HelpButton id="client-admission" />
          </h1>
          <p>{t("adm.intro")}</p>
        </div>
      </div>
      {error && <div className="error">{t(error)}</div>}
      {data && <PolicyCard policy={data.policy} />}
      <SelectedCard options={options} />
      <SubnetsCard subnets={data?.subnets || []} mode={data?.policy.mode} options={options} />
      <ExceptionsCard exceptions={data?.exceptions || []} />
      <section className="card section-spacing">
        <div className="toolbar">
          <label className="search">
            <Search size={16} />
            <input type="search" value={query} aria-label={t("adm.search")} placeholder={t("adm.search")} onChange={(e) => setQuery(e.target.value)} />
          </label>
          <label className="checkbox inline-check">
            <span>{t("adm.onlyRequired")}</span>
            <input type="checkbox" checked={onlyRequired} onChange={(e) => setOnlyRequired(e.target.checked)} />
          </label>
          <button
            className="button primary"
            disabled={!checked.length || !options.length}
            onClick={() =>
              modal({
                title: "adm.requireSelected",
                info: t("adm.requireSelectedInfo"),
                fields: [
                  { name: "router_id", label: "adm.gateRouterMany", type: "select", options },
                  { name: "reason", label: "reason" },
                ],
                submit: async (v) => {
                  const r = await api("/admission/selected", "POST", { ...v, device_ids: checked });
                  setChecked([]);
                  return r;
                },
              })
            }
          >
            {t("adm.requireSelected")} ({checked.length})
          </button>
        </div>
        {data && (
          <div className="explorer-counts compact">
            {["ENROLLED", "ENROLLMENT_PENDING", "NOT_ENROLLED"].map((k) => (
              <div key={k} className="count-chip">
                <strong>{data.counts[k]}</strong>
                <span>{t("adm.client." + k)}</span>
              </div>
            ))}
          </div>
        )}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    aria-label={t("adm.selectAll")}
                    checked={!!data?.items.length && checked.length === data.items.filter((r) => !r.exempt).length}
                    onChange={(e) => setChecked(e.target.checked ? (data?.items || []).filter((r) => !r.exempt).map((r) => r.device_id) : [])}
                  />
                </th>
                {["hostname", "adm.user", "mac", "adm.clientCol", "adm.agentCol", "adm.networkCol", "lastSeen"].map((k) => (
                  <th key={k}>{t(k)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data?.items.map((r) => (
                <tr key={r.device_id} className="clickable" tabIndex={0} aria-selected={selected === r.device_id}
                    onClick={() => setSelected(r.device_id)} onKeyDown={(e) => e.key === "Enter" && setSelected(r.device_id)}>
                  <td onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" aria-label={t("adm.selectRow") + " " + r.hostname} disabled={r.exempt}
                           checked={checked.includes(r.device_id)} onChange={() => toggle(r.device_id)} />
                  </td>
                  <td><b>{r.hostname}</b>{r.required && <small>{t(r.source === "ALL" ? "adm.requiredSubnet" : "adm.required")}</small>}</td>
                  <td>{r.user ? [r.user.military_rank, r.user.full_name].filter(Boolean).join(" ") : "—"}</td>
                  <td className="mono">{r.mac}</td>
                  <td><Badge value={r.client} prefix="adm.client." /></td>
                  <td><Badge value={r.agent} prefix="adm.agent." /></td>
                  <td><Badge value={r.network} prefix="adm.network." /></td>
                  <td>{when(r.last_heartbeat)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {data && !data.items.length && <div className="empty">{t("adm.noDevices")}</div>}
        </div>
      </section>
      {selected && (
        <section className="card section-spacing detail-content">
          <AdmissionDevicePanel deviceId={selected} />
        </section>
      )}
    </>
  );
}

function PolicyCard({ policy }: { policy: any }) {
  const t = useT();
  const { modal } = useContext(WorkContext);
  const [form, setForm] = useState(policy);
  const set = (key: string, value: any) => setForm({ ...form, [key]: value });
  const toggles = ["require_enrollment", "require_running_agent", "require_compliance", "exempt_developers", "auto_revoke", "onboarding_enabled"];
  return (
    <section className="card detail-content">
      <h2>
        <ShieldCheck size={18} /> {t("adm.policy")}
      </h2>
      <div className="admission-grid">
        <label>
          <span>{t("adm.mode")}</span>
          <select value={form.mode} aria-label={t("adm.mode")} aria-describedby="admission-mode-hint" onChange={(e) => set("mode", e.target.value)}>
            {["DISABLED", "PILOT", "GROUPS", "ALL"].map((m) => (
              <option key={m} value={m} disabled={m === "GROUPS"}>
                {t("adm.mode." + m)}
              </option>
            ))}
          </select>
          <small id="admission-mode-hint">{t("adm.modeHint")}</small>
        </label>
        {[["heartbeat_timeout_seconds", 60, 3600], ["grace_seconds", 0, 3600]].map(([key, min, max]) => (
          <label key={key as string}>
            <span>{t("adm." + key)}</span>
            <span className="with-unit">
              <input type="number" min={min as number} max={max as number} value={form[key as string]} onChange={(e) => set(key as string, Number(e.target.value))} />
              <span>{t("unit.seconds")}</span>
            </span>
          </label>
        ))}
        <label>
          <span>{t("adm.outage_policy")}</span>
          <select value={form.outage_policy} aria-label={t("adm.outage_policy")} onChange={(e) => set("outage_policy", e.target.value)}>
            {["EXPIRE", "HOLD"].map((v) => (
              <option key={v} value={v}>
                {t("adm.outage." + v)}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="admission-toggles">
        {toggles.map((key) => (
          <label key={key} className="checkbox">
            <span>
              {t("adm." + key)}
              <small>{t("adm." + key + ".help")}</small>
            </span>
            <input type="checkbox" checked={!!form[key]} onChange={(e) => set(key, e.target.checked)} />
          </label>
        ))}
      </div>
      {form.mode !== policy.mode && form.mode !== "DISABLED" && (
        <p className="notice warning">
          <AlertTriangle size={15} /> {t("adm.enableWarning")}
        </p>
      )}
      <button
        className="button primary"
        onClick={() =>
          modal({
            title: "adm.savePolicy",
            info: t("adm.savePolicyInfo"),
            fields: [{ name: "reason", label: "reason" }],
            submit: (v) => api("/admission/policy", "PUT", { ...form, reason: v.reason }),
          })
        }
      >
        {t("adm.savePolicy")}
      </button>
    </section>
  );
}

function SelectedCard({ options }: { options: { value: string; label: string }[] }) {
  const t = useT();
  const { modal } = useContext(WorkContext);
  const [plan, setPlan] = useState<any>(null);
  return (
    <section className="card section-spacing detail-content">
      <h2>{t("adm.pilot")}</h2>
      <p className="muted">{t("adm.pilotHint")}</p>
      <div className="button-row">
        <button
          className="button secondary"
          disabled={!options.length}
          onClick={() =>
            modal({
              title: "adm.addPilot",
              info: t("adm.addPilotInfo"),
              fields: [
                { name: "mac", label: "adm.pilotMac" },
                { name: "hostname", label: "hostname", required: false },
                { name: "router_id", label: "adm.gateRouter", type: "select", options },
                { name: "reason", label: "reason" },
              ],
              submit: (v) => api("/admission/pilot", "POST", { ...v, hostname: v.hostname || null }),
            })
          }
        >
          {t("adm.addPilot")}
        </button>
        <button
          className="button primary"
          disabled={!options.length}
          onClick={() =>
            modal({
              title: "adm.prepareSelected",
              info: t("adm.prepareSelectedInfo"),
              fields: [
                { name: "router_id", label: "adm.gateRouterMany", type: "select", options },
                { name: "reason", label: "reason" },
              ],
              submit: async (v) =>
                setPlan({ ...(await api(`/admission/routers/${v.router_id}/gate-preview`, "POST", { reason: v.reason })), router_id: v.router_id, reason: v.reason }),
            })
          }
        >
          {t("adm.prepareSelected")}
        </button>
      </div>
      {!options.length && <p className="notice">{t("adm.noRouters")}</p>}
      {plan && (
        <ApplyPlan
          title="adm.prepareSelected"
          plan={plan}
          url={`/admission/routers/${plan.router_id}/apply`}
          onDone={() => setPlan(null)}
          before={
            <>
              {plan.included?.length > 0 && <p>{t("adm.batchIncluded")}: {plan.included.map((i: any) => i.hostname).join(", ")}</p>}
              {plan.skipped?.map((s: any) => (
                <p key={s.device_id} className="notice warning">
                  <AlertTriangle size={15} /> {s.hostname}: {s.blockers.map((b: string) => t(b)).join("; ")}
                </p>
              ))}
            </>
          }
        />
      )}
    </section>
  );
}

function SubnetsCard({ subnets, mode, options }: { subnets: Subnet[]; mode?: string; options: { value: string; label: string }[] }) {
  const t = useT();
  const { modal } = useContext(WorkContext);
  const [plan, setPlan] = useState<any>(null);
  const preview = (subnet: Subnet, kind: "preview" | "removal-preview") =>
    modal({
      title: kind === "preview" ? "adm.subnetPreview" : "adm.subnetRemove",
      info: t(kind === "preview" ? "adm.subnetPreviewInfo" : "adm.subnetRemoveInfo"),
      fields: [{ name: "reason", label: "reason" }],
      submit: async (v) => setPlan({ ...(await api(`/admission/subnets/${subnet.id}/${kind}`, "POST", v)), kind, subnet, reason: v.reason }),
    });
  return (
    <section className="card section-spacing detail-content">
      <h2>{t("adm.subnets")}</h2>
      <p className="muted">{t("adm.subnetsHint")}</p>
      {mode !== "ALL" && <p className="notice">{t("adm.subnetsNeedAll")}</p>}
      {subnets.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {["adm.subnet", "adm.gateRouterMany", "adm.subnetState", "adm.subnetMembers", ""].map((k) => (
                  <th key={k}>{k && t(k)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {subnets.map((s) => (
                <tr key={s.id}>
                  <td className="mono">{s.cidr}</td>
                  <td>{s.router_name || "—"}</td>
                  <td>
                    <span className={"badge " + (TONE[s.state] || "")}>{t("adm.subnetState." + s.state)}</span>
                    {s.error && <small className="error">{t(s.error)}</small>}
                  </td>
                  <td>{s.granted} / {s.members}</td>
                  <td className="button-row">
                    {["PREPARING", "PREVIEW", "ERROR"].includes(s.state) && (
                      <button className="button primary" onClick={() => preview(s, "preview")}>{t("adm.subnetPreview")}</button>
                    )}
                    {s.state !== "NOT_INSTALLED" && (
                      <button className="button secondary danger" onClick={() => preview(s, "removal-preview")}>{t("adm.subnetRemove")}</button>
                    )}
                    {s.state === "NOT_INSTALLED" && (
                      <button
                        className="button secondary"
                        onClick={() =>
                          modal({ title: "adm.subnetDelete", fields: [{ name: "reason", label: "reason" }], submit: (v) => api(`/admission/subnets/${s.id}`, "DELETE", v) })
                        }
                      >
                        {t("adm.subnetDelete")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <button
        className="button secondary"
        disabled={mode !== "ALL" || !options.length}
        onClick={() =>
          modal({
            title: "adm.subnetAdd",
            info: t("adm.subnetAddInfo"),
            fields: [
              { name: "router_id", label: "adm.gateRouterMany", type: "select", options },
              { name: "cidr", label: "adm.subnet" },
              { name: "reason", label: "reason" },
            ],
            submit: (v) => api("/admission/subnets", "POST", v),
          })
        }
      >
        {t("adm.subnetAdd")}
      </button>
      {plan && (
        <ApplyPlan
          title={plan.kind === "preview" ? "adm.subnetPreview" : "adm.subnetRemove"}
          plan={plan}
          url={`/admission/subnets/${plan.subnet.id}/apply`}
          danger={plan.kind !== "preview"}
          confirmCount={plan.plan?.confirm_restricted}
          onDone={() => setPlan(null)}
          before={
            <>
              {plan.feasibility && <Feasibility f={plan.feasibility} />}
              {plan.feasibility?.restricted?.length > 0 && (
                <details open>
                  <summary>{t("adm.subnetRestrictedList")} ({plan.feasibility.facts.hosts_restricted})</summary>
                  <ul className="plain-list">
                    {plan.feasibility.restricted.map((h: any) => (
                      <li key={h.address}>
                        <span className="mono">{h.address}</span> · <span className="mono">{h.mac}</span> {h.hostname || ""}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
              <details>
                <summary>{t("adm.manualRollback")}</summary>
                <p className="muted">{t("adm.subnetRollbackInfo")}</p>
                <pre className="json-view">{(plan.rollback_commands || []).join("\n")}</pre>
              </details>
            </>
          }
        />
      )}
    </section>
  );
}

function ExceptionsCard({ exceptions }: { exceptions: Exempted[] }) {
  const t = useT();
  const { modal } = useContext(WorkContext);
  return (
    <section className="card section-spacing detail-content">
      <h2>{t("adm.exceptions")}</h2>
      <p className="muted">{t("adm.exceptionsHint")}</p>
      {exceptions.length > 0 ? (
        <ul className="plain-list">
          {exceptions.map((e) => (
            <li key={e.device_id}>
              <b>{e.hostname}</b> · <span className="mono">{e.mac}</span> · {t("adm.class." + e.device_class)}
              {e.reason && <> — {e.reason}</>}
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">{t("adm.noExceptions")}</p>
      )}
      <button
        className="button secondary"
        onClick={() =>
          modal({
            title: "adm.exceptionAdd",
            info: t("adm.exceptionAddInfo"),
            fields: [
              { name: "mac", label: "mac" },
              { name: "name", label: "hostname" },
              { name: "device_class", label: "adm.deviceType", type: "select", options: ["OTHER", "INFRASTRUCTURE"].map((c) => ({ value: c, label: t("adm.class." + c) })) },
              { name: "reason", label: "reason" },
            ],
            submit: (v) => api("/admission/exceptions", "POST", { ...v, device_class: v.device_class || "OTHER" }),
          })
        }
      >
        {t("adm.exceptionAdd")}
      </button>
    </section>
  );
}

function Feasibility({ f }: { f: any }) {
  const t = useT();
  return (
    <>
      <div className="detail-grid">
        {Object.entries(f.facts).map(([k, v]) => (
          <div key={k}>
            <span>{t("adm.fact." + k)}</span>
            <strong>{Array.isArray(v) ? v.join(", ") || "—" : typeof v === "boolean" ? t(v ? "ps.on" : "ps.off") : String(v ?? "—")}</strong>
          </div>
        ))}
      </div>
      {f.blockers.map((b: string) => (
        <p key={b} className="error" role="alert">{t(b)}</p>
      ))}
      {f.warnings.map((w: string) => (
        <p key={w} className="notice warning">
          <AlertTriangle size={15} /> {t(w)}
        </p>
      ))}
    </>
  );
}

/** A reviewed router plan for several computers or a subnet: exact operations, then an explicit apply. */
function ApplyPlan({ title, plan, url, before, danger, confirmCount, onDone }: {
  title: string; plan: any; url: string; before?: any; danger?: boolean; confirmCount?: number; onDone: () => void;
}) {
  const t = useT();
  const { refresh } = useContext(WorkContext);
  const [result, setResult] = useState(""),
    [busy, setBusy] = useState(false),
    [typed, setTyped] = useState("");
  const needsCount = confirmCount !== undefined && confirmCount !== null;
  return (
    <section className="plan-review">
      <h3>{t(title)}</h3>
      {before}
      {plan.already_installed && <p className="notice">{t("adm.alreadyInstalled")}</p>}
      {plan.already_removed && <p className="notice">{t("adm.alreadyRemoved")}</p>}
      {plan.plan && (
        <>
          <p>{t("adm.planOps")}</p>
          <pre className="json-view">{plan.plan.operations.map((o: any) => `${o.action} ${o.path} ${JSON.stringify(o.rule || o.owned_comment)}`).join("\n")}</pre>
          <p className="notice">{t("adm.planSafety")}</p>
          {needsCount && (
            <label>
              <span>{t("adm.confirmRestricted")}</span>
              <input type="number" min={0} value={typed} aria-label={t("adm.confirmRestricted")} onChange={(e) => setTyped(e.target.value)} />
            </label>
          )}
          <button
            className={"button " + (danger ? "danger" : "primary")}
            disabled={busy || (needsCount && typed !== String(confirmCount))}
            onClick={async () => {
              setBusy(true);
              try {
                const r = await api(url, "POST", { plan_id: plan.plan.id, reason: plan.reason, ...(needsCount ? { confirm_restricted: Number(typed) } : {}) });
                setResult("adm.applyState." + r.state);
              } catch (e: any) {
                setResult(e.code || "request.failed");
              } finally {
                setBusy(false);
              }
            }}
          >
            {t("adm.applyPlan")}
          </button>
        </>
      )}
      {(result || !plan.plan) && (
        <p className="notice" role="status">
          {result && t(result)} <button className="link-button" onClick={() => (onDone(), refresh())}>{t("adm.close")}</button>
        </p>
      )}
    </section>
  );
}

/** Everything about one computer's Suro Client requirement; also shown on the device page. */
export function AdmissionDevicePanel({ deviceId }: { deviceId: string }) {
  const t = useT();
  const { revision, modal, refresh } = useContext(WorkContext);
  const { data: r, error } = useData<Row>("/admission/devices/" + deviceId, revision);
  const [plan, setPlan] = useState<any>(null);
  const requests = useData<{ id: string; requested: boolean; approved: boolean; expires_at: string; csr_sha256: string | null }[]>(
    "/devices/" + deviceId + "/enrollments",
    revision,
  );
  if (!r) return error ? <div className="error">{t(error)}</div> : null;
  const pending = (requests.data || []).filter((e) => e.requested && !e.approved && new Date(e.expires_at + (e.expires_at.endsWith("Z") ? "" : "Z")) > new Date());
  const base = "/admission/devices/" + deviceId;
  const ask = (title: string, path: string, extra: any = {}, fields: any[] = [], info?: string) =>
    modal({
      title,
      info: info ? t(info) : undefined,
      fields: [...fields, { name: "reason", label: "reason" }],
      submit: (v) => api(path, path.endsWith("admission-exemption") ? "PUT" : path === base ? "PATCH" : "POST", { ...extra, ...v }),
    });
  const preview = (kind: "gate-preview" | "removal-preview") =>
    modal({
      title: kind === "gate-preview" ? "adm.prepareGate" : "adm.removeGate",
      info: t(kind === "gate-preview" ? "adm.prepareGateInfo" : "adm.removeGateInfo"),
      fields: [{ name: "reason", label: "reason" }],
      submit: async (v) => setPlan({ ...(await api(base + "/" + kind, "POST", v)), kind, reason: v.reason }),
    });
  const grid: [string, any][] = [
    ["mac", <span className="mono">{r.mac}</span>],
    ["adm.deviceType", t("adm.class." + r.device_class)],
    ["adm.user", r.user ? [r.user.first_name || r.user.full_name, r.user.last_name].filter(Boolean).join(" ") : "—"],
    ["militaryRank", r.user?.military_rank || "—"],
    ["adm.enrollmentId", r.enrollment_id ? <span className="mono">{r.enrollment_id}</span> : "—"],
    ["agent", r.agent_version || "—"],
    ["lastSeen", when(r.last_heartbeat)],
    ["adm.registered", when(r.registered_at)],
    ["adm.connectedAp", r.connected_ap || "—"],
    ["adm.grantedIp", r.granted_ip || "—"],
    ["adm.grantExpires", r.grant_expires_at ? when(r.grant_expires_at) : r.applied === "AUTHORIZED" ? t("adm.noExpiry") : "—"],
    ["adm.gate", r.gate_state ? t("adm.gate." + r.gate_state) : "—"],
  ];
  return (
    <>
      <h2>{r.hostname}</h2>
      <span className="chips">
        <Badge value={r.client} prefix="adm.client." />
        <Badge value={r.agent} prefix="adm.agent." />
        <Badge value={r.network} prefix="adm.network." />
        {r.exempt && <span className="badge verified">{t("adm.exempt")}</span>}
      </span>
      <p className="notice">
        {t("adm.decision")}: <b>{t("adm.desired." + r.desired)}</b> — {t(r.reason)}
        {r.override && <> · {t("adm.overrideActive")}: {t("adm.override." + r.override)}</>}
      </p>
      {r.error && (
        <p className="error" role="alert">
          {t("adm.lastError")}: {t(r.error)}
        </p>
      )}
      {pending.map((e) => (
        <div key={e.id} className="notice warning" role="status">
          <p>
            {t("adm.approvePending")} <span className="mono">{(e.csr_sha256 || "").slice(0, 16)}</span>
          </p>
          <button
            className="button primary"
            onClick={() =>
              modal({
                title: "adm.approve",
                info: t("adm.approveInfo"),
                submit: () => api(`/devices/${deviceId}/enrollments/${e.id}/approve`, "POST", {}),
              })
            }
          >
            {t("adm.approve")}
          </button>
        </div>
      ))}
      <div className="detail-grid">
        {grid.map(([k, v]) => (
          <div key={k}>
            <span>{t(k)}</span>
            <strong>{v}</strong>
          </div>
        ))}
      </div>
      <div className="button-row">
        {r.required !== undefined && r.gate_state !== null && (
          <>
            {r.gate_state !== "INSTALLED" && <button className="button primary" onClick={() => preview("gate-preview")}>{t("adm.prepareGate")}</button>}
            <button className="button secondary" onClick={() => ask("adm.onboarding", base + "/onboarding-window", {}, [{ name: "minutes", label: "adm.minutes", type: "number", value: 120 }], "adm.onboardingInfo")}>
              {t("adm.onboarding")}
            </button>
            <button className="button secondary" onClick={() => ask("adm.authorizeNow", base + "/override", { action: "AUTHORIZE" }, [{ name: "minutes", label: "adm.minutes", type: "number", value: 60 }], "adm.authorizeInfo")}>
              {t("adm.authorizeNow")}
            </button>
            <button className="button secondary danger" onClick={() => ask("adm.revokeNow", base + "/override", { action: "RESTRICT" }, [], "adm.revokeInfo")}>
              {t("adm.revokeNow")}
            </button>
            {r.override && <button className="button secondary" onClick={() => ask("adm.clearOverride", base + "/override", { action: "CLEAR" })}>{t("adm.clearOverride")}</button>}
            <button className="button secondary" onClick={() => ask(r.required ? "adm.requirementOff" : "adm.requirementOn", base, { enabled: !r.required }, [], r.required ? "adm.requirementOffInfo" : undefined)}>
              {t(r.required ? "adm.requirementOff" : "adm.requirementOn")}
            </button>
            {r.gate_state === "INSTALLED" && <button className="button secondary danger" onClick={() => preview("removal-preview")}>{t("adm.removeGate")}</button>}
          </>
        )}
        <button className="button secondary" onClick={() => ask("adm.resetEnrollment", "/devices/" + deviceId + "/reset-enrollment", {}, [], "adm.resetEnrollmentInfo")}>
          {t("adm.resetEnrollment")}
        </button>
        <button className="button secondary" onClick={() => ask("adm.exemption", "/devices/" + deviceId + "/admission-exemption", { exempt: !r.exempt }, [], r.exempt ? "adm.exemptionOffInfo" : "adm.exemptionInfo")}>
          {t(r.exempt ? "adm.removeExemption" : "adm.exemption")}
        </button>
      </div>
      {plan && <PlanReview plan={plan} deviceId={deviceId} onDone={() => (setPlan(null), refresh())} />}
      {r.rollback_commands && (
        <details>
          <summary>{t("adm.manualRollback")}</summary>
          <p className="muted">{t("adm.manualRollbackInfo")}</p>
          <pre className="json-view">{r.rollback_commands.join("\n")}</pre>
        </details>
      )}
      {r.logs && (
        <details>
          <summary>{t("adm.logs")}</summary>
          <ul className="plain-list">
            {r.logs.map((l, i) => (
              <li key={i}>
                {when(l.at)} — {t(l.action)} {l.details?.error ? `(${t(l.details.error)})` : l.details?.reason ? `(${t(l.details.reason)})` : ""}
              </li>
            ))}
          </ul>
        </details>
      )}
    </>
  );
}

function PlanReview({ plan, deviceId, onDone }: { plan: any; deviceId: string; onDone: () => void }) {
  const t = useT();
  const [result, setResult] = useState<string>(""),
    [busy, setBusy] = useState(false);
  const f = plan.feasibility;
  return (
    <section className="plan-review">
      <h3>{t(plan.kind === "gate-preview" ? "adm.prepareGate" : "adm.removeGate")}</h3>
      {f && (
        <>
          <div className="detail-grid">
            {Object.entries(f.facts).map(([k, v]) => (
              <div key={k}>
                <span>{t("adm.fact." + k)}</span>
                <strong>{Array.isArray(v) ? v.join(", ") || "—" : typeof v === "boolean" ? t(v ? "ps.on" : "ps.off") : String(v ?? "—")}</strong>
              </div>
            ))}
          </div>
          {f.blockers.map((b: string) => (
            <p key={b} className="error" role="alert">{t(b)}</p>
          ))}
          {f.warnings.map((w: string) => (
            <p key={w} className="notice warning">
              <AlertTriangle size={15} /> {t(w)}
            </p>
          ))}
        </>
      )}
      {plan.already_installed && <p className="notice">{t("adm.alreadyInstalled")}</p>}
      {plan.plan && (
        <>
          <p>{t("adm.planOps")}</p>
          <pre className="json-view">{plan.plan.operations.map((o: any) => `${o.action} ${o.path} ${JSON.stringify(o.rule || o.owned_comment)}`).join("\n")}</pre>
          <p className="notice">{t("adm.planSafety")}</p>
          <button
            className={"button " + (plan.kind === "gate-preview" ? "primary" : "danger")}
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                const r = await api("/admission/devices/" + deviceId + "/apply", "POST", { plan_id: plan.plan.id, reason: plan.reason });
                setResult("adm.applyState." + r.state);
              } catch (e: any) {
                setResult(e.code || "request.failed");
              } finally {
                setBusy(false);
              }
            }}
          >
            {t("adm.applyPlan")}
          </button>
        </>
      )}
      {result && (
        <p className="notice" role="status">
          {t(result)} <button className="link-button" onClick={onDone}>{t("adm.close")}</button>
        </p>
      )}
    </section>
  );
}
