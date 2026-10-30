import { useContext, useState } from "react";
import { AlertTriangle, Search, ShieldCheck } from "lucide-react";
import { api } from "../api/client";
import { WorkContext } from "../context";
import { useData } from "../hooks/useData";
import { useT } from "../i18n";
import { HelpButton } from "../components/Help";

// Requested changes and router-confirmed state are always shown apart; see services/admission_gate.py.
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
  rollback_commands?: string[];
  logs?: { at: string; action: string; actor: string; details: any }[];
};
const TONE: Record<string, string> = {
  AUTHORIZED: "online", ENROLLED: "online", CONNECTED: "online", EXEMPT: "verified",
  RESTRICTED: "failed", ERROR: "failed", NOT_ENROLLED: "failed", NEVER: "failed", UNHEALTHY: "failed",
  AUTHORIZATION_PENDING: "pending", REVOCATION_PENDING: "pending", ENROLLMENT_PENDING: "pending", DISCONNECTED: "pending",
};
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
    [onlyRequired, setOnlyRequired] = useState(false);
  const { data, error } = useData<{ policy: any; counts: Record<string, number>; items: Row[] }>(
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
      <PilotCard />
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
                {["hostname", "adm.user", "mac", "adm.clientCol", "adm.agentCol", "adm.networkCol", "lastSeen"].map((k) => (
                  <th key={k}>{t(k)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data?.items.map((r) => (
                <tr key={r.device_id} className="clickable" tabIndex={0} aria-selected={selected === r.device_id}
                    onClick={() => setSelected(r.device_id)} onKeyDown={(e) => e.key === "Enter" && setSelected(r.device_id)}>
                  <td><b>{r.hostname}</b>{r.required && <small>{t("adm.required")}</small>}</td>
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
              <option key={m} value={m} disabled={m === "GROUPS" || m === "ALL"}>
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

function PilotCard() {
  const t = useT();
  const { revision, modal } = useContext(WorkContext);
  const routers = useData<any[]>("/mikrotik/routers", revision);
  const options = (routers.data || []).filter((r) => !r.controller_id && !r.archived).map((r) => ({ value: r.id, label: r.name }));
  return (
    <section className="card section-spacing detail-content">
      <h2>{t("adm.pilot")}</h2>
      <p className="muted">{t("adm.pilotHint")}</p>
      <button
        className="button primary"
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
      {!options.length && <p className="notice">{t("adm.noRouters")}</p>}
    </section>
  );
}

/** Everything about one computer's Suro Client requirement; also shown on the device page. */
export function AdmissionDevicePanel({ deviceId }: { deviceId: string }) {
  const t = useT();
  const { revision, modal, refresh } = useContext(WorkContext);
  const { data: r, error } = useData<Row>("/admission/devices/" + deviceId, revision);
  const [plan, setPlan] = useState<any>(null);
  if (!r) return error ? <div className="error">{t(error)}</div> : null;
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
