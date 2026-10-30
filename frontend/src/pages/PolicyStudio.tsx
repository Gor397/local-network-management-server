import { useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Copy, FilePlus2, Lock, Plus, Search, Trash2 } from "lucide-react";
import { api, ApiError, type FieldError } from "../api/client";
import { WorkContext } from "../context";
import { useData } from "../hooks/useData";
import { useT } from "../i18n";
import { HelpButton } from "../components/Help";
import type { HelpId } from "../help/catalog";

// Everything below is rendered from GET /policies/catalog (backend/app/policies/catalog.py), so a control
// exists only for a real, validated policy field and shows honestly how Windows applies it.
type Setting = {
  id: string;
  key: string;
  category: string;
  control: "toggle" | "text" | "number" | "select" | "list" | "allowances" | "checks" | "flag" | "protected" | "unavailable";
  enforcement: string;
  risk: string;
  value?: string;
  unit?: string;
  min?: number;
  max?: number;
  options?: string[];
  format?: string;
  max_items?: number;
  feature?: string;
  visible_if?: Record<string, any[]>;
};
type Catalog = {
  categories: string[];
  settings: Setting[];
  templates: Record<string, any>;
  checks: Record<string, { source: string; severity: string }>;
  default: Record<string, any>;
  management: { remote: string; protocol: string; ports: number[] } | null;
};
type Change = { key: string; before: any; after: any; risk: string; automatic: boolean; added?: any[]; removed?: any[] };
type Doc = Record<string, any>;

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const CIDR = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(\d|[12]\d|3[0-2])$/;

function visible(s: Setting, doc: Doc) {
  return !s.visible_if || Object.entries(s.visible_if).every(([k, values]) => values.includes(doc[k]));
}
function settingFor(catalog: Catalog, key: string) {
  return catalog.settings.find((s) => s.id === key) || catalog.settings.find((s) => s.key === key);
}

export function PolicyStudio({ id }: { id?: string }) {
  return id ? <PolicyEditor id={id} /> : <PolicyList />;
}

function PolicyList() {
  const t = useT();
  const { revision, modal } = useContext(WorkContext);
  const { data, error } = useData<any[]>("/policies", revision);
  const [query, setQuery] = useState("");
  const rows = (data || []).filter((p) => (p.name + " " + p.description).toLowerCase().includes(query.toLowerCase()));
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>
            {t("policies")} <HelpButton id="policies" />
          </h1>
          <p>{t("ps.intro")}</p>
        </div>
        <div className="heading-actions">
          <button className="button primary" onClick={() => modal({ title: "ps.newPolicy", content: <NewPolicy policies={data || []} /> })}>
            <FilePlus2 size={17} />
            {t("ps.newPolicy")}
          </button>
        </div>
      </div>
      {error && <div className="error">{t(error)}</div>}
      <section className="card">
        <div className="toolbar">
          <label className="search">
            <Search size={16} />
            <input type="search" value={query} aria-label={t("ps.searchPolicies")} placeholder={t("ps.searchPolicies")} onChange={(e) => setQuery(e.target.value)} />
          </label>
        </div>
        {rows.length ? (
          <div className="policy-cards">
            {rows.map((p) => (
              <a key={p.id} className="policy-card" href={"#policies/" + p.id}>
                <h2>{p.name}</h2>
                {p.description && <p>{p.description}</p>}
                <span className="chips">
                  {p.active_sequence ? (
                    <span className="badge online">
                      {t("ps.published")} · {t("version")} {p.active_sequence}
                    </span>
                  ) : (
                    <span className="badge pending">{t("ps.notPublished")}</span>
                  )}
                  {p.has_draft && <span className="badge unknown">{t("ps.draftChanges")}</span>}
                  {p.is_template && <span className="badge">{t("ps.template")}</span>}
                  <span className="count-tag">
                    {p.devices} {t("ps.computers")}
                  </span>
                </span>
              </a>
            ))}
          </div>
        ) : (
          <div className="empty">
            <h3>{t("ps.noPolicies")}</h3>
            <p>{t("ps.noPoliciesHint")}</p>
          </div>
        )}
      </section>
    </>
  );
}

function NewPolicy({ policies }: { policies: any[] }) {
  const t = useT();
  const { modal, refresh } = useContext(WorkContext);
  const [name, setName] = useState(""),
    [description, setDescription] = useState(""),
    [source, setSource] = useState("template:standard"),
    [error, setError] = useState("");
  const create = async () => {
    setError("");
    try {
      const [kind, value] = source.split(":");
      const created = await api("/policies", "POST", {
        name,
        description,
        ...(kind === "template" ? { template: value } : { from_policy_id: value }),
      });
      refresh();
      modal(null);
      location.hash = "policies/" + created.id;
    } catch (e: any) {
      setError(e.code || "request.failed");
    }
  };
  const sources = [
    ...["standard", "restricted", "maintenance", "custom"].map((v) => ({ value: "template:" + v, title: t("ps.template." + v), hint: t("ps.template." + v + ".hint") })),
    ...policies.map((p) => ({ value: "policy:" + p.id, title: t("ps.copyOf") + " " + p.name, hint: p.is_template ? t("ps.template") : p.description })),
  ];
  return (
    <div className="modal-content">
      <label>
        <span>{t("name")}</span>
        <input value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} />
      </label>
      <label>
        <span>{t("ps.description")}</span>
        <input value={description} onChange={(e) => setDescription(e.target.value)} maxLength={2000} />
      </label>
      <fieldset className="choice-list">
        <legend>{t("ps.startFrom")}</legend>
        {sources.map((s) => (
          <label key={s.value} className={"choice" + (source === s.value ? " active" : "")}>
            <input type="radio" name="source" value={s.value} checked={source === s.value} onChange={() => setSource(s.value)} />
            <span>
              <b>{s.title}</b>
              {s.hint && <small>{s.hint}</small>}
            </span>
          </label>
        ))}
      </fieldset>
      {error && <div className="error">{t(error)}</div>}
      <div className="modal-footer">
        <button className="button secondary" onClick={() => modal(null)}>
          {t("cancel")}
        </button>
        <button className="button primary" disabled={!name.trim()} onClick={create}>
          {t("ps.createDraft")}
        </button>
      </div>
    </div>
  );
}

function PolicyEditor({ id }: { id: string }) {
  const t = useT();
  const { revision, modal, refresh, identity } = useContext(WorkContext);
  const policy = useData<any>("/policies/" + id, revision);
  const catalog = useData<Catalog>("/policies/catalog");
  const [doc, setDoc] = useState<Doc | null>(null),
    [savedDoc, setSavedDoc] = useState<Doc | null>(null),
    [tab, setTab] = useState("settings"),
    [errors, setErrors] = useState<FieldError[]>([]),
    [warnings, setWarnings] = useState<FieldError[]>([]),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false);
  const loadedFor = useRef("");
  const p = policy.data;
  const active = p?.versions?.find((v: any) => v.id === p.active_version_id)?.document;
  // Initialise the working copy once per policy (and after save/publish), never on background refreshes.
  useEffect(() => {
    if (!p || !catalog.data) return;
    const key = p.id + ":" + (p.draft_updated_at || "") + ":" + (p.active_version_id || "");
    if (loadedFor.current === key) return;
    if (loadedFor.current.startsWith(p.id + ":") && dirtyRef.current) return;
    loadedFor.current = key;
    const base = { ...catalog.data.default, ...(p.draft || active || catalog.data.default) };
    setDoc(base);
    setSavedDoc(base);
  }, [p, catalog.data]);
  const dirty = !!doc && JSON.stringify(doc) !== JSON.stringify(savedDoc);
  const dirtyRef = useRef(false);
  dirtyRef.current = dirty;
  useEffect(() => {
    const warn = (e: BeforeUnloadEvent) => {
      if (dirtyRef.current) e.preventDefault();
    };
    // Capture link clicks before the app navigates, so "stay" really keeps the unsaved edits.
    const guard = (e: MouseEvent) => {
      const link = (e.target as HTMLElement).closest?.("a[href^='#']");
      if (link && dirtyRef.current && link.getAttribute("href") !== "#policies/" + id && !confirm(t("ps.unsavedConfirm"))) {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    addEventListener("beforeunload", warn);
    document.addEventListener("click", guard, true);
    return () => {
      removeEventListener("beforeunload", warn);
      document.removeEventListener("click", guard, true);
    };
  }, [id, t]);
  // Server validation is authoritative; it runs shortly after edits stop, once per pause.
  useEffect(() => {
    if (!doc || !dirty) return;
    const timer = setTimeout(() => {
      api("/policies/validate", "POST", { document: doc })
        .then((r) => {
          setErrors(r.errors);
          setWarnings(r.warnings);
        })
        .catch(() => {});
    }, 600);
    return () => clearTimeout(timer);
  }, [doc]);
  if (!p || !catalog.data || !doc)
    return policy.error ? <div className="error">{t(policy.error)}</div> : <div className="empty">{t("loading")}</div>;
  const canEdit = identity.role === "owner" || identity.role === "operator";
  const save = async () => {
    setBusy(true);
    setNotice("");
    try {
      const r = await api("/policies/" + id + "/draft", "PUT", { document: doc, expected_draft_at: p.draft_updated_at });
      setSavedDoc(r.document);
      setDoc(r.document);
      setErrors([]);
      setWarnings(r.warnings);
      loadedFor.current = p.id + ":" + r.draft_updated_at + ":" + (p.active_version_id || "");
      setNotice("ps.draftSaved");
      refresh();
      return true;
    } catch (e: any) {
      if (e instanceof ApiError && e.fields.length) setErrors(e.fields);
      setNotice(e.code || "request.failed");
      return false;
    } finally {
      setBusy(false);
    }
  };
  const review = async () => {
    if (dirty && !(await save())) return;
    modal({ title: "ps.reviewPublish", content: <ReviewPublish policy={p} catalog={catalog.data!} /> });
  };
  const hasDraft = p.draft !== null && p.draft !== undefined;
  return (
    <>
      <a className="back-button" href="#policies">
        ← {t("policies")}
      </a>
      <div className="page-heading">
        <div>
          <h1>{p.name}</h1>
          <p>{p.description || t("ps.noDescription")}</p>
          <span className="chips">
            {p.active_version_id ? (
              <span className="badge online">
                {t("ps.published")} · {t("version")} {p.versions.find((v: any) => v.id === p.active_version_id)?.sequence}
              </span>
            ) : (
              <span className="badge pending">{t("ps.notPublished")}</span>
            )}
            {hasDraft && <span className="badge unknown">{t("ps.draftChanges")}</span>}
            {dirty && <span className="badge high">{t("ps.unsaved")}</span>}
          </span>
        </div>
        <div className="heading-actions">
          <button className="button secondary" onClick={() => modal({ title: "ps.newPolicy", content: <DuplicatePolicy policy={p} /> })}>
            <Copy size={16} />
            {t("ps.duplicate")}
          </button>
          {hasDraft && p.active_version_id && (
            <button
              className="button secondary"
              onClick={() =>
                confirm(t("ps.discardConfirm")) &&
                api("/policies/" + id + "/draft", "DELETE").then(() => {
                  loadedFor.current = "";
                  setSavedDoc(null);
                  refresh();
                })
              }
            >
              {t("ps.discardDraft")}
            </button>
          )}
          {canEdit && (
            <>
              <button className="button secondary" disabled={!dirty || busy || errors.length > 0} onClick={save}>
                {t("ps.saveDraft")}
              </button>
              <button className="button primary" disabled={busy || errors.length > 0 || (!dirty && !hasDraft)} onClick={review}>
                {t("ps.reviewPublish")}
              </button>
            </>
          )}
        </div>
      </div>
      {notice && (
        <div className={notice === "ps.draftSaved" ? "notice" : "error"} role="status">
          {t(notice)}
        </div>
      )}
      <div className="tabs" role="tablist">
        {["settings", "assign", "compliance", "history", "advanced"].map((v) => (
          <button key={v} role="tab" aria-selected={tab === v} className={tab === v ? "active" : ""} onClick={() => setTab(v)}>
            {t("ps.tab." + v)}
          </button>
        ))}
      </div>
      {tab === "settings" ? (
        <SettingsPanel catalog={catalog.data} doc={doc} setDoc={setDoc} errors={errors} warnings={warnings} base={active} readOnly={!canEdit} />
      ) : tab === "assign" ? (
        <AssignPanel policy={p} doc={doc} />
      ) : tab === "compliance" ? (
        <CompliancePanel policyId={id} catalog={catalog.data} />
      ) : tab === "history" ? (
        <HistoryPanel policy={p} catalog={catalog.data} onRestored={() => (loadedFor.current = "")} />
      ) : (
        <AdvancedPanel doc={doc} setDoc={setDoc} readOnly={!canEdit} />
      )}
    </>
  );
}

function DuplicatePolicy({ policy }: { policy: any }) {
  const t = useT();
  const { modal, refresh } = useContext(WorkContext);
  const [name, setName] = useState(t("ps.copyOf") + " " + policy.name),
    [template, setTemplate] = useState(false),
    [error, setError] = useState("");
  return (
    <div className="modal-content">
      <label>
        <span>{t("name")}</span>
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <label className="checkbox">
        <span>{t("ps.saveAsTemplate")}</span>
        <input type="checkbox" checked={template} onChange={(e) => setTemplate(e.target.checked)} />
      </label>
      {error && <div className="error">{t(error)}</div>}
      <div className="modal-footer">
        <button className="button secondary" onClick={() => modal(null)}>
          {t("cancel")}
        </button>
        <button
          className="button primary"
          onClick={() =>
            api("/policies", "POST", { name, from_policy_id: policy.id, is_template: template, description: policy.description })
              .then((r) => {
                refresh();
                modal(null);
                location.hash = "policies/" + r.id;
              })
              .catch((e) => setError(e.code))
          }
        >
          {t("ps.duplicate")}
        </button>
      </div>
    </div>
  );
}

function EnforcementBadge({ s }: { s: Setting }) {
  const t = useT();
  const tone = { agent: "online", approval: "pending", detected: "", server: "", protected: "verified", unavailable: "failed" }[s.enforcement];
  return (
    <span className={"badge " + tone} title={t("enforcement." + s.enforcement + ".help")}>
      {s.enforcement === "protected" && <Lock size={11} />}
      {t("enforcement." + s.enforcement)}
    </span>
  );
}

function SettingsPanel({
  catalog,
  doc,
  setDoc,
  errors,
  warnings,
  base,
  readOnly,
}: {
  catalog: Catalog;
  doc: Doc;
  setDoc: (d: Doc) => void;
  errors: FieldError[];
  warnings: FieldError[];
  base?: Doc;
  readOnly: boolean;
}) {
  const t = useT();
  const [category, setCategory] = useState(catalog.categories[0]),
    [query, setQuery] = useState("");
  const needle = query.trim().toLowerCase();
  const matches = (s: Setting) =>
    !needle || (t("policySetting." + s.id) + " " + t("policySetting." + s.id + ".help")).toLowerCase().includes(needle);
  const shown = catalog.settings.filter((s) => (needle ? matches(s) : s.category === category) && visible(s, doc));
  const changedIn = (c: string) =>
    base ? catalog.settings.filter((s) => s.category === c && s.key in doc && JSON.stringify(doc[s.key]) !== JSON.stringify(base[s.key])).length : 0;
  const problems = (s: Setting) => [...errors, ...warnings].filter((e) => e.field === s.key || e.field?.startsWith(s.key + "."));
  const unplaced = errors.filter((e) => !catalog.settings.some((s) => e.field === s.key || e.field?.startsWith(s.key + ".")));
  return (
    <div className="policy-studio">
      <nav className="card policy-categories" aria-label={t("ps.categories")}>
        <label className="search">
          <Search size={16} />
          <input type="search" value={query} aria-label={t("ps.searchSettings")} placeholder={t("ps.searchSettings")} onChange={(e) => setQuery(e.target.value)} />
        </label>
        {catalog.categories.map((c) => (
          <button key={c} className={!needle && category === c ? "active" : ""} aria-current={!needle && category === c} onClick={() => (setQuery(""), setCategory(c))}>
            <span>{t("policyCategory." + c)}</span>
            {changedIn(c) > 0 && <span className="count-tag">{changedIn(c)}</span>}
          </button>
        ))}
      </nav>
      <section className="policy-settings">
        {!needle && <p className="category-hint">{t("policyCategory." + category + ".hint")}</p>}
        {unplaced.map((e, i) => (
          <div key={i} className="error" role="alert">
            {t(e.code)}
          </div>
        ))}
        {shown.length === 0 && <div className="empty">{t("ps.noMatchingSettings")}</div>}
        {shown.map((s) => (
          <article key={s.id} className={"setting-card" + (problems(s).some((e) => errors.includes(e)) ? " invalid" : "")}>
            <div className="setting-text">
              <h3>
                {t("policySetting." + s.id)} <HelpButton id={("policy-" + s.category) as HelpId} />
              </h3>
              <p>{t("policySetting." + s.id + ".help")}</p>
              <span className="chips">
                <EnforcementBadge s={s} />
                {s.risk !== "safe" && <span className="badge high">{t("risk." + s.risk)}</span>}
                {s.feature && <span className="badge">{t("ps.needsAgent02")}</span>}
              </span>
              {problems(s).map((e, i) => (
                <div key={i} className={errors.includes(e) ? "field-error" : "field-warning"} role={errors.includes(e) ? "alert" : "status"}>
                  <AlertTriangle size={14} /> {t(e.code)}
                  {e.value && <code> {e.value}</code>}
                  {e.fix && !readOnly && (
                    <button className="link-button" onClick={() => setDoc({ ...doc, firewall_allowances: [...doc.firewall_allowances, e.fix] })}>
                      {t("ps.addManagementRule")}
                    </button>
                  )}
                </div>
              ))}
            </div>
            <div className="setting-control">
              <Control s={s} doc={doc} setDoc={setDoc} readOnly={readOnly} catalog={catalog} />
            </div>
          </article>
        ))}
      </section>
    </div>
  );
}

function Control({ s, doc, setDoc, readOnly, catalog }: { s: Setting; doc: Doc; setDoc: (d: Doc) => void; readOnly: boolean; catalog: Catalog }) {
  const t = useT();
  const set = (value: any) => setDoc({ ...doc, [s.key]: value });
  const label = t("policySetting." + s.id);
  if (s.control === "protected")
    return (
      <span className="locked">
        <Lock size={15} /> {t("ps.alwaysOn")}
      </span>
    );
  if (s.control === "unavailable") return <span className="locked muted">{t("ps.notAvailable")}</span>;
  if (s.control === "toggle" || s.control === "flag") {
    const list: string[] = doc[s.key] || [];
    const on = s.control === "toggle" ? !!doc[s.key] : list.includes(s.value!);
    return (
      <label className="switch">
        <input
          type="checkbox"
          role="switch"
          aria-label={label}
          checked={on}
          disabled={readOnly}
          onChange={(e) => (s.control === "toggle" ? set(e.target.checked) : set(e.target.checked ? [...list, s.value] : list.filter((v) => v !== s.value)))}
        />
        <span aria-hidden="true" />
        <b>{t(on ? "ps.on" : "ps.off")}</b>
      </label>
    );
  }
  if (s.control === "number")
    return (
      <span className="with-unit">
        <input type="number" aria-label={label} min={s.min} max={s.max} value={doc[s.key] ?? ""} disabled={readOnly} onChange={(e) => set(e.target.value === "" ? s.min ?? 0 : Number(e.target.value))} />
        <span>{t("unit." + s.unit)}</span>
      </span>
    );
  if (s.control === "select")
    return (
      <select aria-label={label} value={doc[s.key]} disabled={readOnly} onChange={(e) => set(e.target.value)}>
        {s.options!.map((o) => (
          <option key={o} value={o}>
            {t("policyOption." + s.id + "." + o)}
          </option>
        ))}
      </select>
    );
  if (s.control === "text") {
    const value = doc[s.key] ?? "";
    const bad = value && ((s.format === "ipv4" && !IPV4.test(value)) || (s.format === "cidr" && !CIDR.test(value)));
    return (
      <>
        <input aria-label={label} aria-invalid={!!bad} value={value} disabled={readOnly} placeholder={s.format ? t("placeholder." + s.format) : undefined} onChange={(e) => set(e.target.value.trim() || null)} />
        {bad && <small className="field-error">{t(s.format === "cidr" ? "policy.invalid_prefix" : "policy.invalid_address")}</small>}
      </>
    );
  }
  if (s.control === "list") return <ListEditor label={label} values={doc[s.key] || []} format={s.format} max={s.max_items || 20} readOnly={readOnly} onChange={set} />;
  if (s.control === "allowances") return <AllowanceEditor values={doc[s.key] || []} management={catalog.management} readOnly={readOnly} onChange={set} />;
  if (s.control === "checks")
    return (
      <div className="check-grid">
        {s.options!.map((c) => (
          <label key={c} className="checkbox">
            <span>{t("check." + c)}</span>
            <input
              type="checkbox"
              checked={(doc[s.key] || []).includes(c)}
              disabled={readOnly}
              onChange={(e) => set(e.target.checked ? [...doc[s.key], c] : doc[s.key].filter((v: string) => v !== c))}
            />
          </label>
        ))}
      </div>
    );
  return null;
}

function ListEditor({ label, values, format, max, readOnly, onChange }: { label: string; values: string[]; format?: string; max: number; readOnly: boolean; onChange: (v: string[]) => void }) {
  const t = useT();
  const [next, setNext] = useState("");
  const invalid = format === "ipv4" && next !== "" && !IPV4.test(next);
  const add = () => {
    if (next.trim() && !invalid && !values.includes(next.trim())) onChange([...values, next.trim()]);
    setNext("");
  };
  return (
    <div className="list-editor">
      <ul className="tag-list">
        {values.map((v) => (
          <li key={v}>
            <span>{v}</span>
            {!readOnly && (
              <button aria-label={t("remove") + " " + v} onClick={() => onChange(values.filter((x) => x !== v))}>
                <Trash2 size={13} />
              </button>
            )}
          </li>
        ))}
      </ul>
      {!readOnly && values.length < max && (
        <span className="inline-add">
          <input aria-label={label} value={next} aria-invalid={invalid} placeholder={format ? t("placeholder." + format) : undefined} onChange={(e) => setNext(e.target.value)} onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), add())} />
          <button className="button secondary" disabled={invalid || !next.trim()} onClick={add}>
            <Plus size={15} /> {t("ps.add")}
          </button>
        </span>
      )}
      {invalid && <small className="field-error">{t("policy.invalid_address")}</small>}
    </div>
  );
}

const SERVICES: Record<string, { protocol: string; ports: number[] }> = {
  web: { protocol: "TCP", ports: [443] },
  dns: { protocol: "UDP", ports: [53] },
  files: { protocol: "TCP", ports: [445] },
  printer: { protocol: "TCP", ports: [9100] },
  remote_desktop: { protocol: "TCP", ports: [3389] },
  custom: { protocol: "TCP", ports: [] },
};

function AllowanceEditor({ values, management, readOnly, onChange }: { values: any[]; management: Catalog["management"]; readOnly: boolean; onChange: (v: any[]) => void }) {
  const t = useT();
  const [service, setService] = useState("web"),
    [address, setAddress] = useState(""),
    [ports, setPorts] = useState("");
  const isManagement = (a: any) => management && a.remote === management.remote && a.protocol === "TCP" && a.ports.includes(management.ports[0]);
  const valid = IPV4.test(address) || CIDR.test(address);
  const add = () => {
    const preset = SERVICES[service];
    const list = service === "custom" ? ports.split(/[ ,]+/).filter(Boolean).map(Number) : preset.ports;
    onChange([...values, { remote: address.includes("/") ? address : address + "/32", protocol: preset.protocol, ports: list }]);
    setAddress("");
    setPorts("");
  };
  return (
    <div className="allowance-editor">
      <ul className="tag-list wide">
        {values.map((a, i) => (
          <li key={i}>
            <span>
              {isManagement(a) && <Lock size={12} />} <code>{a.remote}</code> {a.protocol} {a.ports.join(", ") || t("ps.allPorts")}
              {isManagement(a) && <small> · {t("ps.managementRule")}</small>}
            </span>
            {!readOnly && !isManagement(a) && (
              <button aria-label={t("remove")} onClick={() => onChange(values.filter((_, j) => j !== i))}>
                <Trash2 size={13} />
              </button>
            )}
          </li>
        ))}
      </ul>
      {!readOnly && (
        <div className="allowance-add">
          <select aria-label={t("ps.service")} value={service} onChange={(e) => setService(e.target.value)}>
            {Object.keys(SERVICES).map((k) => (
              <option key={k} value={k}>
                {t("ps.service." + k)}
              </option>
            ))}
          </select>
          <input aria-label={t("ps.allowedAddress")} placeholder={t("placeholder.address")} value={address} onChange={(e) => setAddress(e.target.value.trim())} />
          {service === "custom" && <input aria-label={t("ps.ports")} placeholder="8080, 8443" value={ports} onChange={(e) => setPorts(e.target.value)} />}
          <button className="button secondary" disabled={!valid} onClick={add}>
            <Plus size={15} /> {t("ps.add")}
          </button>
        </div>
      )}
    </div>
  );
}

export function formatValue(t: (k: string) => string, catalog: Catalog, key: string, value: any): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return t(value ? "ps.on" : "ps.off");
  if (key === "auto_remediate") return value.length ? value.map((v: string) => t("autoOp." + v)).join(", ") : t("ps.none");
  if (key === "mandatory_checks") return `${value.length} ${t("ps.checksCount")}`;
  if (key === "firewall_allowances") return value.length ? value.map((a: any) => `${a.remote} ${a.protocol} ${a.ports.join(",")}`).join("; ") : t("ps.none");
  const s = settingFor(catalog, key);
  if (s?.control === "select") return t("policyOption." + s.id + "." + value);
  if (Array.isArray(value)) return value.length ? value.join(", ") : t("ps.none");
  if (typeof value === "object") return JSON.stringify(value);
  return s?.unit ? `${value} ${t("unit." + s.unit)}` : String(value);
}

function ChangeTable({ changes, catalog }: { changes: Change[]; catalog: Catalog }) {
  const t = useT();
  return changes.length ? (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{t("ps.setting")}</th>
            <th>{t("ps.current")}</th>
            <th>{t("ps.new")}</th>
            <th>{t("ps.impact")}</th>
          </tr>
        </thead>
        <tbody>
          {changes.map((c) => (
            <tr key={c.key}>
              <td>
                <b>{t("policySetting." + (settingFor(catalog, c.key)?.id || c.key))}</b>
              </td>
              <td>{formatValue(t, catalog, c.key, c.before)}</td>
              <td>{formatValue(t, catalog, c.key, c.after)}</td>
              <td>
                <span className={"badge " + (c.risk === "safe" ? "online" : c.risk === "high" ? "failed" : "pending")}>{t("risk." + c.risk)}</span>
                <small>{t(c.automatic ? "ps.appliedAutomatically" : "ps.notAppliedAutomatically")}</small>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <p className="notice">{t("ps.noChanges")}</p>
  );
}

function ReviewPublish({ policy, catalog }: { policy: any; catalog: Catalog }) {
  const t = useT();
  const { modal, refresh } = useContext(WorkContext);
  const [preview, setPreview] = useState<any>(null),
    [reason, setReason] = useState(""),
    [understood, setUnderstood] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    api("/policies/" + policy.id + "/preview", "POST", {}).then(setPreview).catch((e) => setError(e.code));
  }, [policy.id]);
  if (!preview) return <div className="modal-content">{error ? <div className="error">{t(error)}</div> : t("loading")}</div>;
  const risky = preview.changes.some((c: Change) => c.risk !== "safe");
  const groups = ["high", "network", "restart", "safe"].filter((r) => preview.changes.some((c: Change) => c.risk === r));
  return (
    <div className="modal-content review">
      <h2>
        {preview.affected.devices
          ? t("ps.affects").replace("{n}", String(preview.affected.devices))
          : t(preview.first_version ? "ps.firstVersion" : "ps.noComputersYet")}
      </h2>
      {preview.affected.devices > 0 && (
        <p>
          {t("ps.onlineOffline").replace("{online}", String(preview.affected.online)).replace("{offline}", String(preview.affected.offline))}
        </p>
      )}
      {groups.map((r) => (
        <section key={r}>
          <h3>{t("risk." + r + ".title")}</h3>
          <p className="muted">{t("risk." + r + ".explain")}</p>
          <ChangeTable changes={preview.changes.filter((c: Change) => c.risk === r)} catalog={catalog} />
        </section>
      ))}
      {preview.changes.length === 0 && <p className="notice">{t("ps.noChanges")}</p>}
      {preview.warnings.map((w: FieldError, i: number) => (
        <div key={i} className="field-warning">
          <AlertTriangle size={14} /> {t(w.code)}
        </div>
      ))}
      <p className="notice">{t("ps.desiredNotForced")}</p>
      <label>
        <span>{t("reason")}</span>
        <input value={reason} onChange={(e) => setReason(e.target.value)} minLength={5} />
      </label>
      {risky && (
        <label className="checkbox">
          <span>{t("ps.understandRisk")}</span>
          <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} />
        </label>
      )}
      {error && <div className="error">{t(error)}</div>}
      <div className="modal-footer">
        <button className="button secondary" onClick={() => modal(null)}>
          {t("cancel")}
        </button>
        <button
          className="button primary"
          disabled={reason.trim().length < 5 || (risky && !understood)}
          onClick={() =>
            api("/policies/" + policy.id + "/publish", "POST", { reason, expected_version_id: policy.active_version_id })
              .then(() => {
                refresh();
                modal(null);
              })
              .catch((e) => setError(e.code))
          }
        >
          {t("publish")}
        </button>
      </div>
    </div>
  );
}

function AssignPanel({ policy, doc }: { policy: any; doc: Doc }) {
  const t = useT();
  const { revision, modal, refresh } = useContext(WorkContext);
  const [query, setQuery] = useState(""),
    [devices, setDevices] = useState<Set<string>>(new Set()),
    [groups, setGroups] = useState<Set<string>>(new Set()),
    [all, setAll] = useState(false),
    [preview, setPreview] = useState<any>(null),
    [error, setError] = useState("");
  const list = useData<any>("/devices?limit=200&q=" + encodeURIComponent(query), revision);
  const groupList = useData<any[]>("/groups", revision);
  const targets = { device_ids: [...devices], group_ids: [...groups], all_devices: all };
  useEffect(() => setPreview(null), [devices, groups, all]);
  const toggle = (set: Set<string>, value: string, update: (s: Set<string>) => void) => {
    const next = new Set(set);
    next.has(value) ? next.delete(value) : next.add(value);
    update(next);
  };
  const rows = (list.data?.items || []).filter((d: any) => d.device_class !== "DEVELOPER");
  if (!policy.active_version_id) return <div className="notice">{t("ps.publishBeforeAssign")}</div>;
  return (
    <div className="assign-flow">
      <ol className="steps">
        <li className="done">{t("ps.step.policy")}</li>
        <li className={preview ? "done" : "current"}>{t("ps.step.targets")}</li>
        <li className={preview ? "current" : ""}>{t("ps.step.review")}</li>
      </ol>
      <p className="notice">{t("ps.precedence")}</p>
      <section className="card assign-targets">
        <label className="checkbox all-target">
          <span>
            <b>{t("ps.allComputers")}</b>
            <small>{t("ps.allComputersHint")}</small>
          </span>
          <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />
        </label>
        {!all && (
          <div className="target-columns">
            <div>
              <h3>{t("device-groups")}</h3>
              <p className="muted">{t("ps.groupsNotAp")}</p>
              {(groupList.data || []).map((g) => (
                <label key={g.id} className="checkbox">
                  <span>{g.name}</span>
                  <input type="checkbox" checked={groups.has(g.id)} onChange={() => toggle(groups, g.id, setGroups)} />
                </label>
              ))}
              {!groupList.data?.length && <p className="muted">{t("ps.noGroups")}</p>}
            </div>
            <div>
              <h3>{t("ps.computers")}</h3>
              <label className="search">
                <Search size={16} />
                <input type="search" value={query} aria-label={t("search")} placeholder={t("search")} onChange={(e) => setQuery(e.target.value)} />
              </label>
              <div className="button-row">
                <button className="button secondary" onClick={() => setDevices(new Set([...devices, ...rows.map((d: any) => d.id)]))}>
                  {t("ps.selectShown")}
                </button>
                <button className="button secondary" disabled={!devices.size} onClick={() => setDevices(new Set())}>
                  {t("ps.clearSelection")} ({devices.size})
                </button>
              </div>
              <div className="target-list">
                {rows.map((d: any) => (
                  <label key={d.id} className="checkbox">
                    <span>
                      {d.hostname} <small className="mono">{d.primary_mac}</small>
                    </span>
                    <input type="checkbox" checked={devices.has(d.id)} onChange={() => toggle(devices, d.id, setDevices)} />
                  </label>
                ))}
              </div>
            </div>
          </div>
        )}
        <div className="button-row">
          <button
            className="button primary"
            disabled={!all && !devices.size && !groups.size}
            onClick={() =>
              api("/policies/" + policy.id + "/assignment-preview", "POST", targets)
                .then(setPreview)
                .catch((e) => setError(e.code))
            }
          >
            {t("ps.reviewAssignment")}
          </button>
        </div>
      </section>
      {error && <div className="error">{t(error)}</div>}
      {preview && (
        <section className="card assign-review">
          <h2>{t("ps.assignCount").replace("{n}", String(preview.total))}</h2>
          <ul className="plain-list">
            <li>{t("ps.assignOnline").replace("{n}", String(preview.online))}</li>
            <li>{t("ps.assignOffline").replace("{n}", String(preview.offline))}</li>
            {preview.already > 0 && <li>{t("ps.assignAlready").replace("{n}", String(preview.already))}</li>}
            {Object.entries(preview.replacing).map(([name, n]) => (
              <li key={name}>{t("ps.assignReplacing").replace("{n}", String(n)).replace("{policy}", name)}</li>
            ))}
          </ul>
          <button
            className="button primary"
            disabled={!preview.total}
            onClick={() =>
              modal({
                title: "ps.applyAssignment",
                info: t("ps.assignConfirm").replace("{n}", String(preview.total)),
                fields: [{ name: "reason", label: "reason" }],
                submit: async (v) => {
                  await api("/policies/" + policy.id + "/assign-targets", "POST", { ...targets, reason: v.reason });
                  setPreview(null);
                  refresh();
                },
              })
            }
          >
            {t("ps.applyAssignment")}
          </button>
        </section>
      )}
      {doc.ip_mode === "static" && <StaticAddresses policy={policy} doc={doc} />}
    </div>
  );
}

function StaticAddresses({ policy, doc }: { policy: any; doc: Doc }) {
  const t = useT();
  const { revision, modal } = useContext(WorkContext);
  const layers = useData<any[]>("/policies/" + policy.id + "/layers", revision);
  const assigned = useData<any>("/policies/" + policy.id + "/compliance", revision);
  const rows = (layers.data || []).filter((l) => l.scope === "DEVICE" && l.controls.static_ip_address);
  const names = new Map((assigned.data?.devices || []).map((d: any) => [d.id, d.hostname]));
  return (
    <section className="card section-spacing detail-content">
      <h2>{t("ps.staticAddresses")}</h2>
      <p className="muted">{t("ps.staticAddressesHint").replace("{prefix}", doc.ip_prefix || "—")}</p>
      <ul className="plain-list">
        {rows.map((l) => (
          <li key={l.id}>
            <b>{String(names.get(l.target) || l.target)}</b> — <code>{l.controls.static_ip_address}</code>
          </li>
        ))}
      </ul>
      <button
        className="button secondary"
        disabled={!assigned.data?.devices?.length}
        onClick={() =>
          modal({
            title: "ps.addStaticAddress",
            info: t("ps.staticAfterPublish"),
            fields: [
              { name: "target", label: "ps.computer", type: "select", options: (assigned.data?.devices || []).map((d: any) => ({ value: d.id, label: d.hostname })) },
              { name: "address", label: "ps.address" },
              { name: "reason", label: "reason" },
            ],
            submit: (v) =>
              api("/policies/" + policy.id + "/layers", "POST", { scope: "DEVICE", target: v.target, controls: { static_ip_address: v.address }, reason: v.reason }),
          })
        }
      >
        <Plus size={15} /> {t("ps.addStaticAddress")}
      </button>
    </section>
  );
}

function CompliancePanel({ policyId, catalog }: { policyId: string; catalog: Catalog }) {
  const t = useT();
  const { revision } = useContext(WorkContext);
  const { data, error } = useData<any>("/policies/" + policyId + "/compliance", revision);
  const [open, setOpen] = useState<string | null>(null),
    [filter, setFilter] = useState("total");
  const keys = ["total", "compliant", "noncompliant", "applying", "awaiting_approval", "reboot_required", "failed", "offline", "not_reported"];
  const test: Record<string, (d: any) => boolean> = {
    total: () => true,
    compliant: (d) => d.state === "COMPLIANT",
    noncompliant: (d) => d.state === "NONCOMPLIANT",
    applying: (d) => d.applying,
    awaiting_approval: (d) => d.awaiting_approval,
    reboot_required: (d) => d.reboot_required,
    failed: (d) => d.failed,
    offline: (d) => !d.online,
    not_reported: (d) => d.not_reported,
  };
  if (!data) return error ? <div className="error">{t(error)}</div> : <div className="empty">{t("loading")}</div>;
  const rows = data.devices.filter(test[filter]);
  return (
    <>
      <p className="notice">{t("ps.complianceTruth")}</p>
      <div className="explorer-counts">
        {keys.map((k) => (
          <button key={k} className={"count-chip" + (filter === k ? " active" : "")} aria-pressed={filter === k} onClick={() => setFilter(k)}>
            <strong>{data.counts[k]}</strong>
            <span>{t("ps.count." + k)}</span>
          </button>
        ))}
      </div>
      <section className="card">
        {rows.length ? (
          <ul className="compliance-list">
            {rows.map((d: any) => (
              <li key={d.id}>
                <button className="tree-row" aria-expanded={open === d.id} onClick={() => setOpen(open === d.id ? null : d.id)}>
                  <span className="tree-label">
                    <b>{d.hostname}</b>
                    <small>
                      {t("ps.evaluatedVersion")}: {d.evaluated_sequence ?? "—"} / {t("ps.assignedVersion")}: {d.assigned_sequence ?? "—"}
                    </small>
                  </span>
                  <span className="chips">
                    <span className={"badge " + d.state.toLowerCase()}>{t(d.state)}</span>
                    {!d.online && <span className="badge">{t("ps.count.offline")}</span>}
                    {d.applying && <span className="badge pending">{t("ps.count.applying")}</span>}
                    {d.reboot_required && <span className="badge pending">{t("ps.count.reboot_required")}</span>}
                    {d.failed && <span className="badge failed">{t("ps.count.failed")}</span>}
                  </span>
                </button>
                {open === d.id && (
                  <div className="detail-content">
                    <p className="muted">
                      {t("ps.lastVerified")}: {d.last_verified ? new Date(d.last_verified + "Z").toLocaleString() : "—"}
                    </p>
                    {d.failing.length ? (
                      <ul className="requirement-list">
                        {d.failing.map((c: any) => (
                          <li key={c.check_id}>
                            <span className={"badge " + (c.status === "FAIL" ? "failed" : "unknown")}>{t(c.status === "FAIL" ? "ps.missing" : "ps.notVerified")}</span>
                            <b>{t("check." + c.check_id)}</b>
                            <small>{t("check." + c.check_id + ".fix")}</small>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p>{t(d.state === "COMPLIANT" ? "ps.allMet" : "ps.noReportYet")}</p>
                    )}
                    {catalog && (
                      <a className="button secondary" href={"#devices/" + d.id}>
                        {t("ps.viewRemediation")}
                      </a>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <div className="empty">{t("ps.noComputersHere")}</div>
        )}
      </section>
    </>
  );
}

function HistoryPanel({ policy, catalog, onRestored }: { policy: any; catalog: Catalog; onRestored: () => void }) {
  const t = useT();
  const { modal, refresh } = useContext(WorkContext);
  const releases = policy.versions.filter((v: any) => !v.compiled);
  const [base, setBase] = useState(releases[1]?.id || ""),
    [target, setTarget] = useState(releases[0]?.id || ""),
    [changes, setChanges] = useState<Change[] | null>(null);
  const label = (v: any) => `${t("version")} ${v.sequence} · ${new Date(v.created_at + "Z").toLocaleString()}`;
  if (!releases.length) return <div className="notice">{t("ps.noVersions")}</div>;
  return (
    <>
      <section className="card detail-content">
        <h2>{t("ps.compare")}</h2>
        <div className="toolbar compare-bar">
          <select aria-label={t("ps.compareFrom")} value={base} onChange={(e) => setBase(e.target.value)}>
            {releases.map((v: any) => (
              <option key={v.id} value={v.id}>
                {label(v)}
              </option>
            ))}
          </select>
          <span>→</span>
          <select aria-label={t("ps.compareTo")} value={target} onChange={(e) => setTarget(e.target.value)}>
            {policy.draft && <option value="draft">{t("ps.draftChanges")}</option>}
            {releases.map((v: any) => (
              <option key={v.id} value={v.id}>
                {label(v)}
              </option>
            ))}
          </select>
          <button className="button secondary" disabled={!base || !target} onClick={() => api(`/policies/${policy.id}/diff?base=${base}&target=${target}`).then((r) => setChanges(r.changes))}>
            {t("ps.compare")}
          </button>
        </div>
        {changes && <ChangeTable changes={changes} catalog={catalog} />}
      </section>
      <section className="card section-spacing">
        {releases.map((v: any) => (
          <div className="version-row" key={v.id}>
            <div>
              <b>
                {t("version")} {v.sequence} {v.id === policy.active_version_id && <span className="badge online">{t("ps.active")}</span>}
              </b>
              <small>
                {new Date(v.created_at + "Z").toLocaleString()} · {v.author || "—"}
              </small>
              <p>{v.reason}</p>
            </div>
            {v.id !== policy.active_version_id && (
              <button
                className="button secondary"
                onClick={() =>
                  modal({
                    title: "ps.restoreToDraft",
                    info: t("ps.restoreHint"),
                    submit: async () => {
                      await api("/policies/" + policy.id + "/restore", "POST", { version_id: v.id });
                      onRestored();
                      refresh();
                    },
                  })
                }
              >
                {t("ps.restoreToDraft")}
              </button>
            )}
          </div>
        ))}
      </section>
    </>
  );
}

function AdvancedPanel({ doc, setDoc, readOnly }: { doc: Doc; setDoc: (d: Doc) => void; readOnly: boolean }) {
  const t = useT();
  const formatted = useMemo(() => JSON.stringify(doc, null, 2), [doc]);
  const [text, setText] = useState(formatted),
    [result, setResult] = useState<ReactNode>(null);
  useEffect(() => setText(formatted), [formatted]);
  const apply = async () => {
    try {
      const parsed = JSON.parse(text);
      const r = await api("/policies/validate", "POST", { document: parsed });
      if (!r.valid) setResult(r.errors.map((e: FieldError, i: number) => <div key={i} className="field-error">{(e.field ? e.field + ": " : "") + t(e.code)}</div>));
      else {
        setDoc(r.document);
        setResult(<div className="notice"><CheckCircle2 size={14} /> {t("ps.advancedApplied")}</div>);
      }
    } catch {
      setResult(<div className="field-error">{t("invalidJson")}</div>);
    }
  };
  return (
    <section className="card detail-content">
      <p className="notice">{t("ps.advancedHint")}</p>
      <textarea className="policy-json" spellCheck={false} rows={24} value={text} readOnly={readOnly} aria-label={t("ps.tab.advanced")} onChange={(e) => setText(e.target.value)} />
      {!readOnly && (
        <div className="button-row">
          <button className="button secondary" onClick={apply}>
            {t("ps.validateApply")}
          </button>
        </div>
      )}
      {result}
    </section>
  );
}
