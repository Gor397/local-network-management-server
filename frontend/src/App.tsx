import {
  lazy,
  Suspense,
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
  type FormEvent,
} from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  Bell,
  Box,
  Check,
  CheckCheck,
  ChevronRight,
  CircleHelp,
  ClipboardList,
  Command,
  Database,
  Download,
  FileText,
  Globe,
  HardDrive,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Monitor,
  MoreHorizontal,
  Network,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Upload,
  Users,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { Navigation } from "./components/Navigation";
import { WorkContext, type ModalSpec, type Field } from "./context";
import { HelpButton, HelpAction, HelpCenter } from "./components/Help";
import { AdminCredentialPanel } from "./components/AdminCredential";
import { extraRoutes } from "./routes";
const PolicyStudio = lazy(() =>
  import("./pages/PolicyStudio").then((module) => ({ default: module.PolicyStudio })),
);
const AdmissionDevicePanel = lazy(() =>
  import("./pages/AdmissionPage").then((module) => ({ default: module.AdmissionDevicePanel })),
);
const SuroPages = lazy(() =>
  import("./pages/SuroPages").then((module) => ({ default: module.SuroPages })),
);
import { api, setCsrf } from "./api/client";
import { useData } from "./hooks/useData";
import { LocaleContext, useT, initialLanguage, type Language } from "./i18n";
import type { Device, Identity } from "./types";

const routes = [
  ["overview", LayoutDashboard],
  ["devices", Monitor],
  ["policies", ShieldCheck],
  ["network", Network],
  ["software", Box],
  ["deployments", ArrowDownToLine],
  ["sessions", Terminal],
  ["alerts", Bell],
  ["audit", ClipboardList],
  ["settings", Settings],
] as const;
function navigate(path: string) {
  location.hash = path;
}
function time(value: any, language = document.documentElement.lang || "hy") {
  return value
    ? new Date(value.endsWith?.("Z") ? value : value + "Z").toLocaleString(
        language === "hy" ? "hy-AM" : language === "ru" ? "ru-RU" : "en-GB",
        { dateStyle: "medium", timeStyle: "short" },
      )
    : "—";
}
function Badge({ value }: { value: string }) {
  const t = useT();
  return (
    <span className={"badge " + value.toLowerCase()}>
      <i />
      {t(value)}
    </span>
  );
}
function Empty({
  title = "empty",
  children,
}: {
  title?: string;
  children?: ReactNode;
}) {
  const t = useT();
  return (
    <div className="empty">
      <Monitor size={32} />
      <h3>{t(title)}</h3>
      {children}
    </div>
  );
}
function JsonView({ value }: { value: any }) {
  return <pre className="json-view">{JSON.stringify(value, null, 2)}</pre>;
}
function ErrorBox({ code }: { code: string }) {
  const t = useT();
  return code ? (
    <div role="alert" className="error">
      <ShieldAlert size={18} />
      <span>
        {t("error")} · {t("errorCode")}: {t(code)}
      </span>
    </div>
  ) : null;
}
function Form({ spec, onClose }: { spec: ModalSpec; onClose: () => void }) {
  const t = useT();
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const { refresh } = useContext(WorkContext);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(e.currentTarget);
    const values: any = {};
    for (const f of spec.fields || []) {
      const v = form.get(f.name);
      values[f.name] =
        f.type === "checkbox"
          ? v === "on"
          : f.type === "number"
            ? Number(v)
            : v;
    }
    try {
      await spec.submit?.(values);
      refresh();
      onClose();
    } catch (e: any) {
      setError(e.code || "invalidJson");
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit}>
      {spec.info && <div className="notice">{spec.info}</div>}
      <div className="form-fields">
        {spec.fields?.map((f) => (
          <label
            key={f.name}
            className={f.type === "checkbox" ? "checkbox" : ""}
          >
            <span>
              {t(f.label)}
              <HelpButton feature={f.label} />
            </span>
            {f.type === "select" ? (
              <select
                name={f.name}
                defaultValue={f.value}
                required={f.required !== false}
              >
                {f.options?.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            ) : f.type === "textarea" ? (
              <textarea
                name={f.name}
                defaultValue={f.value}
                rows={5}
                required={f.required !== false}
              />
            ) : (
              <input
                name={f.name}
                type={f.type || "text"}
                defaultValue={f.type === "checkbox" ? undefined : f.value}
                defaultChecked={f.type === "checkbox" ? !!f.value : undefined}
                required={f.type === "checkbox" ? false : f.required !== false}
              />
            )}
          </label>
        ))}
      </div>
      <ErrorBox code={error} />
      <div className="modal-footer">
        <button type="button" className="button secondary" onClick={onClose}>
          {t("cancel")}
        </button>
        <HelpAction feature="loading">
          <button disabled={busy} className="button primary">
            {busy ? t("loading") : t("confirm")}
          </button>
        </HelpAction>
      </div>
    </form>
  );
}

export default function App() {
  const [language, setLanguageState] = useState<Language>(initialLanguage);
  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);
  const setLanguage = (value: Language) => {
    setLanguageState(value);
    localStorage.setItem("lantern-language", value);
    document.documentElement.lang = value;
  };
  return (
    <LocaleContext.Provider
      value={{
        language: ["en", "hy", "ru"].includes(language) ? language : "hy",
        setLanguage,
      }}
    >
      <Workspace />
    </LocaleContext.Provider>
  );
}
function ModeBanner() {
  const t = useT(),
    { data } = useData<{ mode: string }>("/safety", 0);
  if (!data) return null;
  return (
    <div className={"mode-banner " + data.mode} role="status">
      {t("mode_" + data.mode)} <HelpButton id="safety-modes" />
    </div>
  );
}

function LanguageSelector() {
  const { language, setLanguage } = useContext(LocaleContext);
  const t = useT();
  return (
    <label className="language">
      <Globe size={16} />
      <select
        aria-label={t("language")}
        value={language}
        onChange={(e) => setLanguage(e.target.value as Language)}
      >
        <option value="en">English</option>
        <option value="hy">Հայերեն</option>
        <option value="ru">Русский</option>
      </select>
    </label>
  );
}
function Workspace() {
  const t = useT();
  const [identity, setIdentity] = useState<Identity | null>(null),
    [checking, setChecking] = useState(true),
    [route, setRoute] = useState(location.hash.slice(1) || "overview"),
    [revision, setRevision] = useState(0),
    [modal, setModal] = useState<ModalSpec | null>(null),
    [toast, setToast] = useState(""),
    [error, setError] = useState("");
  const refresh = () => setRevision((r) => r + 1);
  useEffect(() => {
    api<Identity>("/auth/me")
      .then((me) => {
        setIdentity(me);
        setCsrf(me.csrf);
      })
      .catch(() => {})
      .finally(() => setChecking(false));
    const hash = () => setRoute(location.hash.slice(1) || "overview");
    window.addEventListener("hashchange", hash);
    return () => window.removeEventListener("hashchange", hash);
  }, []);
  useEffect(() => {
    if (!identity) return;
    const events = new EventSource("/api/v1/events");
    events.addEventListener("revision", refresh);
    return () => events.close();
  }, [identity?.username]);
  useEffect(() => {
    if (!toast && !error) return;
    const timeout = setTimeout(() => {
      setToast("");
      setError("");
    }, 7000);
    return () => clearTimeout(timeout);
  }, [toast, error]);
  const run = async (fn: () => Promise<any>) => {
    try {
      const result = await fn();
      setToast(t("saved"));
      refresh();
      return result;
    } catch (e: any) {
      setError(e.code || "request.failed");
      return null;
    }
  };
  if (checking)
    return (
      <div className="boot">
        <Shield size={40} />
        <p>{t("loading")}</p>
      </div>
    );
  if (!identity)
    return (
      <Login
        onLogin={(me) => {
          setCsrf(me.csrf);
          setIdentity(me);
        }}
      />
    );
  const page = route.split("/")[0],
    deviceId = route.split("/")[1];
  const context = { revision, refresh, modal: setModal, run, identity };
  return (
    <WorkContext.Provider value={context}>
      <div className="shell">
        <aside className="sidebar">
          <a href="#overview" className="brand">
            <span className="brand-mark">
              <Command size={24} />
            </span>
            <span>
              Suro<small>{t("brandCaption")}</small>
            </span>
          </a>
          <Navigation page={page} />
          <div className="sidebar-status">
            <span className="status-dot" />
            <span>
              {t("controlPlane")}
              <small>{t("https")}</small>
            </span>
            <LockKeyhole size={14} />
          </div>
          <div className="profile">
            <div className="avatar">{identity.username[0]?.toUpperCase()}</div>
            <span>
              {identity.username}
              <small>{identity.role}</small>
            </span>
            <button
              title={t("logout")}
              onClick={() =>
                run(async () => {
                  await api("/auth/logout", "POST");
                  setIdentity(null);
                  setCsrf("");
                })
              }
            >
              <LogOut size={17} />
            </button>
          </div>
        </aside>
        <div className="workspace">
          <header className="topbar">
            <div className="breadcrumb">
              {t("brandCaption")}
              <ChevronRight size={14} />
              <strong>{t(page)}</strong>
            </div>
            <div className="topbar-actions">
              <LanguageSelector />
              <a href="#alerts" className="icon-button" title={t("alerts")}>
                <Bell size={19} />
              </a>
              <span className="topbar-avatar">
                {identity.username.slice(0, 2).toUpperCase()}
              </span>
            </div>
          </header>
          <ModeBanner />
          <main key={page}>
            {page === "help" ? (
              <HelpCenter />
            ) : extraRoutes.includes(page) ? (
              <Suspense fallback={<p role="status">{t("loading")}</p>}>
                <SuroPages page={page} id={deviceId} />
              </Suspense>
            ) : page === "overview" ? (
              <Overview />
            ) : page === "devices" ? (
              deviceId ? (
                <DeviceDetail id={deviceId} />
              ) : (
                <Devices />
              )
            ) : page === "policies" ? (
              <Suspense fallback={<p role="status">{t("loading")}</p>}>
                <PolicyStudio id={deviceId} />
              </Suspense>
            ) : page === "network" ? (
              <NetworkPage />
            ) : page === "software" ? (
              <Software />
            ) : page === "deployments" ? (
              <Deployments />
            ) : page === "sessions" ? (
              <Sessions />
            ) : page === "alerts" ? (
              <Alerts />
            ) : page === "audit" ? (
              <Audit />
            ) : (
              <SettingsPage />
            )}
          </main>
          <footer className="app-footer">
            <span>
              Suro <b>0.1</b>
            </span>
            <span>
              <LockKeyhole size={12} />
              {t("localOnly")}
            </span>
          </footer>
        </div>
      </div>
      {toast && (
        <div className="toast" role="status">
          <Check size={18} />
          {toast}
        </div>
      )}
      {error && (
        <div className="toast error">
          <ErrorBox code={error} />
        </div>
      )}
      {modal && (
        <div
          className="modal-backdrop"
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setModal(null);
          }}
        >
          <section
            className={"modal " + (modal.content ? "wide" : "")}
            role="dialog"
            aria-modal="true"
            aria-label={t(modal.title)}
          >
            <div className="modal-heading">
              <h2>{t(modal.title)}</h2>
              <button
                className="icon-button"
                onClick={() => setModal(null)}
                title={t("close")}
              >
                <X size={20} />
              </button>
            </div>
            {modal.content || (
              <Form
                spec={modal}
                onClose={() =>
                  setModal((current) => (current === modal ? null : current))
                }
              />
            )}
          </section>
        </div>
      )}
    </WorkContext.Provider>
  );
}
function Login({ onLogin }: { onLogin: (me: Identity) => void }) {
  const t = useT();
  const [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [showOtp, setShowOtp] = useState(false);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    const f = new FormData(e.currentTarget);
    try {
      onLogin(
        await api("/auth/login", "POST", {
          username: f.get("username"),
          password: f.get("password"),
          totp: f.get("totp") || null,
        }),
      );
    } catch (e: any) {
      setError(e.code);
      if (e.code === "auth.invalid_totp") setShowOtp(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="login">
      <div className="login-top">
        <a href="#" className="brand">
          <span className="brand-mark">
            <Command size={24} />
          </span>
          <span>Suro</span>
        </a>
        <LanguageSelector />
      </div>
      <div className="login-panel">
        <span className="eyebrow">
          <span className="status-dot" />
          {t("brandCaption")}
        </span>
        <h1>{t("loginTitle")}</h1>
        <p>{t("loginSubtitle")}</p>
        <form onSubmit={submit}>
          <label>
            {t("username")}
            <input name="username" autoComplete="username" required />
          </label>
          <label>
            {t("password")}
            <input
              type="password"
              name="password"
              autoComplete="current-password"
              required
            />
          </label>
          <HelpAction feature="optionalOtp">
            <button
              type="button"
              className="optional-otp"
              onClick={() => setShowOtp(!showOtp)}
            >
              {t("optionalOtp")}
            </button>
          </HelpAction>
          <HelpButton id="mfa" />
          {showOtp && (
            <label>
              {t("totp")}
              <input
                name="totp"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
              />
            </label>
          )}
          <ErrorBox code={error} />
          <HelpAction feature="loading">
            <button disabled={busy} className="button primary">
              {busy ? t("loading") : t("signIn")}
              <ArrowRight size={17} />
            </button>
          </HelpAction>
        </form>
        <small>
          <LockKeyhole size={13} />
          {t("localOnly")}
        </small>
      </div>
      <div className="login-decoration">
        <div />
        <div />
        <div />
        <Network size={110} />
      </div>
    </div>
  );
}
function Heading({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children?: ReactNode;
}) {
  const t = useT();
  return (
    <div className="page-heading">
      <div>
        <span className="eyebrow">Suro / {t("workspace")}</span>
        <h1>
          {t(title)} <HelpButton feature={title} />
        </h1>
        {subtitle && <p>{t(subtitle)}</p>}
      </div>
      <div className="heading-actions">{children}</div>
    </div>
  );
}
function RegisterButton() {
  const t = useT();
  const { modal, identity } = useContext(WorkContext);
  if (identity.role === "viewer") return null;
  return (
    <HelpAction feature="addDevice">
      <button
        className="button primary"
        onClick={() =>
          modal({
            title: "addDevice",
            fields: [
              { name: "hostname", label: "hostname" },
              { name: "primary_mac", label: "mac" },
              {
                name: "device_class",
                label: "class",
                type: "select",
                options: ["STANDARD", "ADMINISTRATOR", "DEVELOPER"].map(
                  (value) => ({ value, label: t(value) }),
                ),
              },
            ],
            submit: (v) => api("/devices", "POST", v),
            info: t("emptyText"),
          })
        }
      >
        <Plus size={17} />
        {t("addDevice")}
      </button>
    </HelpAction>
  );
}
function Overview() {
  const t = useT();
  const { revision, refresh } = useContext(WorkContext);
  const { data, error } = useData("/dashboard", revision);
  const fleet = useData<{ items: Device[] }>("/devices?limit=5", revision);
  const c = data?.counts || {};
  const stats = [
    ["managed", c.total || 0, Monitor, "neutral"],
    ["online", c.online || 0, Activity, "teal"],
    ["verified", c.COMPLIANT || 0, ShieldCheck, "green"],
    [
      "needsAttention",
      (c.NONCOMPLIANT || 0) + (c.UNVERIFIED || 0),
      ShieldAlert,
      "amber",
    ],
  ] as const;
  return (
    <>
      <Heading title="overview" subtitle="summary">
        <button className="button secondary" onClick={refresh}>
          <RefreshCw size={16} />
          {t("refresh")}
        </button>
        <RegisterButton />
      </Heading>
      <ErrorBox code={error} />
      <div className="stats">
        {stats.map(([label, value, Icon, color]) => (
          <div className={"stat " + color} key={label}>
            <div className="stat-top">
              <span>{t(label)}</span>
              <Icon size={19} />
            </div>
            <strong>{value}</strong>
            <small>
              {label === "managed"
                ? t("registered")
                : label === "verified"
                  ? t("mandatoryNotice")
                  : label === "online"
                    ? t("lastSeen")
                    : t("unverified")}
            </small>
          </div>
        ))}
      </div>
      <div className="overview-grid">
        <section className="card security-card">
          <div className="card-heading">
            <h2>{t("fleetStatus")}</h2>
            <Shield size={18} />
          </div>
          <div className="fleet-chart">
            <div
              className="donut"
              style={{
                background: `conic-gradient(#0b9f85 0deg ${((c.COMPLIANT || 0) / Math.max(c.total || 0, 1)) * 360}deg,#e8edf1 0deg)`,
              }}
            >
              <div>
                <strong>{c.total || 0}</strong>
                <span>{t("devices")}</span>
              </div>
            </div>
            <div className="legend">
              {[
                ["COMPLIANT", "green"],
                ["NONCOMPLIANT", "red"],
                ["UNVERIFIED", "amber"],
                ["QUARANTINED", "violet"],
              ].map(([label, color]) => (
                <div key={label}>
                  <i className={color} />
                  <span>{t(label)}</span>
                  <b>{c[label] || 0}</b>
                </div>
              ))}
            </div>
          </div>
          <div className="card-note">
            <CircleHelp size={15} />
            {t("mandatoryNotice")}
          </div>
        </section>
        <section className="card">
          <div className="card-heading">
            <h2>{t("recentAlerts")}</h2>
            <a href="#alerts">
              {t("viewAll")}
              <ArrowRight size={14} />
            </a>
          </div>
          {data?.alerts?.length ? (
            <div className="alert-feed">
              {data.alerts.map((a: any) => (
                <div key={a.id}>
                  <span className={"alert-icon " + a.severity}>
                    <ShieldAlert size={17} />
                  </span>
                  <div>
                    <strong>{t(a.code)}</strong>
                    <small>{time(a.at)}</small>
                  </div>
                  <Badge value={a.severity} />
                </div>
              ))}
            </div>
          ) : (
            <div className="all-clear">
              <ShieldCheck size={30} />
              <h3>{t("noAlerts")}</h3>
              <p>{t("supportBoundary")}</p>
            </div>
          )}
        </section>
      </div>
      <section className="card inventory-card">
        <div className="card-heading">
          <h2>
            {t("devices")}
            <span className="count-tag">{c.total || 0}</span>
          </h2>
          <a href="#devices">
            {t("viewAll")}
            <ArrowRight size={14} />
          </a>
        </div>
        {fleet.data?.items.length ? (
          <DeviceTable devices={fleet.data.items} />
        ) : (
          <Empty title="emptyTitle">
            <p>{t("emptyText")}</p>
            <RegisterButton />
          </Empty>
        )}
      </section>
      <div className="bottom-grid">
        <div className="info-tile">
          <Zap size={21} />
          <div>
            <h3>{t("lowResource")}</h3>
            <p>{t("lowResourceText")}</p>
          </div>
          <Badge value={data?.low_resource_mode ? "ACTIVE" : "UNKNOWN"} />
        </div>
        <div className="info-tile">
          <ShieldCheck size={21} />
          <div>
            <h3>{t("auditDefault")}</h3>
            <p>{t("auditDefaultText")}</p>
          </div>
        </div>
      </div>
    </>
  );
}
function DeviceTable({ devices }: { devices: Device[] }) {
  const t = useT();
  const { language } = useContext(LocaleContext);
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {[
              "device",
              "mac",
              "ip",
              "ap",
              "class",
              "compliance",
              "network",
              "lastSeen",
            ].map((k) => (
              <th key={k}>{t(k)}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr
              key={d.id}
              onClick={() => navigate("devices/" + d.id)}
              className="clickable"
            >
              <td>
                <div className="device-cell">
                  <span className="device-icon">
                    <Monitor size={17} />
                  </span>
                  <div>
                    <b>{d.hostname}</b>
                    <small>
                      {d.agent_version
                        ? `${t("agent")} ${d.agent_version}`
                        : t(
                            d.device_class === "DEVELOPER"
                              ? "DEVELOPER"
                              : "PENDING_ENROLLMENT",
                          )}
                    </small>
                  </div>
                </div>
              </td>
              <td className="mono">{d.primary_mac}</td>
              <td className="mono">{d.network.ip || "—"}</td>
              <td>{d.network.ap || "—"}</td>
              <td>
                <span className="class-label">{t(d.device_class)}</span>
              </td>
              <td>
                <div className="compliance-cell">
                  <Badge value={d.state} />
                  {d.compliance_score !== null && (
                    <small>{d.compliance_score}%</small>
                  )}
                </div>
              </td>
              <td>
                <span className="network-label">{t(d.network_state)}</span>
              </td>
              <td className="last-seen">{time(d.last_heartbeat, language)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function Devices() {
  const t = useT();
  const { revision } = useContext(WorkContext);
  const [q, setQ] = useState(""),
    [query, setQuery] = useState(""),
    [cls, setCls] = useState(""),
    [page, setPage] = useState(0);
  useEffect(() => {
    const id = setTimeout(() => {
      setQuery(q);
      setPage(0);
    }, 250);
    return () => clearTimeout(id);
  }, [q]);
  const { data, error, loading } = useData<{ items: Device[]; total: number }>(
    `/devices?limit=25&offset=${page * 25}&q=${encodeURIComponent(query)}&device_class=${cls}`,
    revision,
  );
  return (
    <>
      <Heading title="devices" subtitle="emptyText">
        <RegisterButton />
      </Heading>
      <section className="card">
        <div className="toolbar">
          <div className="search">
            <Search size={17} />
            <input
              aria-label={t("search")}
              placeholder={t("search")}
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <select
            aria-label={t("class")}
            value={cls}
            onChange={(e) => {
              setCls(e.target.value);
              setPage(0);
            }}
          >
            <option value="">{t("allClasses")}</option>
            {["STANDARD", "ADMINISTRATOR", "DEVELOPER"].map((v) => (
              <option key={v} value={v}>
                {t(v)}
              </option>
            ))}
          </select>
        </div>
        <ErrorBox code={error} />
        {loading && !data ? (
          <Empty title="loading" />
        ) : data?.items.length ? (
          <DeviceTable devices={data.items} />
        ) : (
          <Empty />
        )}
        <div className="pagination">
          <span>
            {page * 25 + 1}–{Math.min((page + 1) * 25, data?.total || 0)} /{" "}
            {data?.total || 0}
          </span>
          <div>
            <button disabled={!page} onClick={() => setPage((p) => p - 1)}>
              {t("previous")}
            </button>
            <button
              disabled={(page + 1) * 25 >= (data?.total || 0)}
              onClick={() => setPage((p) => p + 1)}
            >
              {t("next")}
            </button>
          </div>
        </div>
      </section>
    </>
  );
}
function DeviceDetail({ id }: { id: string }) {
  const t = useT();
  const { revision, modal, run, refresh } = useContext(WorkContext);
  const { data: d, error } = useData<Device>("/devices/" + id, revision);
  const checks = useData("/devices/" + id + "/compliance", revision);
  const history = useData("/devices/" + id + "/history", revision);
  const health = useData("/devices/" + id + "/health", revision);
  const exceptions = useData<any[]>("/devices/" + id + "/exceptions", revision);
  const requests = useData<any[]>("/devices/" + id + "/enrollments", revision);
  const policies = useData<any[]>("/policies", revision);
  const [tab, setTab] = useState("overview");
  if (!d)
    return (
      <>
        <ErrorBox code={error} />
        <Empty title="loading" />
      </>
    );
  const prompt = (title: string, path: string, extra: any = {}) =>
    modal({
      title,
      info: t("confirmImpact"),
      fields: [{ name: "reason", label: "reason" }],
      submit: async (v) => {
        const result = await api(path, "POST", { ...extra, ...v });
        modal({ title, content: <JsonView value={result} /> });
        return result;
      },
    });
  return (
    <>
      <button className="back-button" onClick={() => navigate("devices")}>
        <ArrowLeft size={15} />
        {t("back")}
      </button>
      <Heading title="device">
        <HelpAction feature="recheck">
          <button
            className="button secondary"
            onClick={() =>
              run(() => api("/devices/" + id + "/recheck", "POST"))
            }
          >
            <RefreshCw size={16} />
            {t("recheck")}
          </button>
        </HelpAction>
        <HelpAction feature="quarantine">
          <button
            className="button secondary"
            onClick={() =>
              prompt(
                "quarantine",
                "/mikrotik/devices/" + id + "/quarantine-preview",
              )
            }
          >
            <ShieldAlert size={16} />
            {t("quarantine")}
          </button>
        </HelpAction>
        <HelpAction feature="release">
          <button
            className="button secondary"
            onClick={() =>
              prompt("release", "/mikrotik/devices/" + id + "/release-preview")
            }
          >
            <ShieldCheck size={16} />
            {t("release")}
          </button>
        </HelpAction>
        {d.device_class !== "DEVELOPER" && (
          <HelpAction feature="ssh">
            <button
              className="button primary"
              onClick={() =>
                modal({
                  title: "ssh",
                  info: t("terminalNotice"),
                  fields: [
                    { name: "reason", label: "reason" },
                    {
                      name: "maintenance_approved",
                      label: "maintenanceApproval",
                      type: "checkbox",
                    },
                  ],
                  submit: async (v) => {
                    const result = await api(
                      "/devices/" + id + "/ssh-sessions",
                      "POST",
                      v,
                    );
                    setTimeout(
                      () =>
                        modal({
                          title: "ssh",
                          content: <TerminalPane session={result} />,
                        }),
                      0,
                    );
                  },
                })
              }
            >
              <Terminal size={16} />
              {t("ssh")}
            </button>
          </HelpAction>
        )}
      </Heading>
      <section className="card device-overview">
        <span className="large-device">
          <Monitor size={30} />
        </span>
        <div>
          <h2>{d.hostname}</h2>
          <span className="mono">{d.primary_mac}</span>
          <small>{d.os_version || t("noEvidence")}</small>
        </div>
        <div className="device-overview-end">
          <Badge value={d.state} />
          <span>
            {d.compliance_score === null
              ? t("DEVELOPER")
              : `${d.compliance_score}%`}
          </span>
          <Badge value={d.mode} />
        </div>
      </section>
      {d.device_class === "DEVELOPER" && (
        <div className="notice">{t("unmanagedNotice")}</div>
      )}
      <div className="tabs">
        {[
          "overview",
          "hardware",
          "users",
          "storage",
          "firewall",
          "compliance",
          "permissions",
          "adminCredentialTab",
          "adm.networkTab",
          "history",
        ].map((v) => (
          <button
            key={v}
            onClick={() => setTab(v)}
            className={tab === v ? "active" : ""}
          >
            {t(v)}
          </button>
        ))}
      </div>
      <section className="card detail-content">
        {tab === "overview" ? (
          <>
            <div className="detail-grid">
              {[
                ["hostname", d.hostname],
                ["ip", d.network.ip],
                ["ap", d.network.ap],
                ["class", t(d.device_class)],
                ["lastSeen", time(d.last_heartbeat)],
                ["policy", d.policy_version_id],
                ["network", t(d.network_state)],
                ["agent", d.agent_version],
              ].map(([k, v]) => (
                <div key={k}>
                  <span>{t(k!)}</span>
                  <strong>{v || "—"}</strong>
                </div>
              ))}
            </div>
            <div className="button-row">
              <HelpAction feature="editDevice">
                <button
                  className="button secondary"
                  onClick={() =>
                    modal({
                      title: "editDevice",
                      fields: [
                        {
                          name: "hostname",
                          label: "hostname",
                          value: d.hostname,
                        },
                        {
                          name: "mode",
                          label: "mode",
                          type: "select",
                          value: d.mode,
                          options: [
                            "AUDIT",
                            "PREVIEW",
                            "APPROVED_REMEDIATION",
                            "CONTINUOUS",
                            "MAINTENANCE",
                          ].map((value) => ({ value, label: t(value) })),
                        },
                        { name: "reason", label: "reason" },
                      ],
                      submit: (v) =>
                        api("/devices/" + id, "PATCH", {
                          ...v,
                          revision: d.revision,
                        }),
                    })
                  }
                >
                  {t("editDevice")}
                </button>
              </HelpAction>
              <HelpAction feature="assignPolicy">
                <button
                  className="button secondary"
                  onClick={() =>
                    modal({
                      title: "assignPolicy",
                      fields: [
                        {
                          name: "policy",
                          label: "policy",
                          type: "select",
                          options: policies.data
                            ?.filter((p) => p.active_version_id)
                            .map((p) => ({
                              value: JSON.stringify(p),
                              label: p.name,
                            })),
                        },
                      ],
                      submit: (v) => {
                        const p = JSON.parse(v.policy);
                        return api("/policies/" + p.id + "/assign", "POST", {
                          device_ids: [id],
                          version_id: p.active_version_id,
                        });
                      },
                    })
                  }
                >
                  {t("assignPolicy")}
                </button>
              </HelpAction>
              <HelpAction feature="createToken">
                <button
                  className="button secondary"
                  onClick={() =>
                    run(async () => {
                      const r = await api(
                        "/devices/" + id + "/enrollment-token",
                        "POST",
                      );
                      modal({
                        title: "createToken",
                        content: (
                          <div className="modal-content">
                            <p>{t("tokenNotice")}</p>
                            <pre className="secret">{r.token}</pre>
                          </div>
                        ),
                      });
                    })
                  }
                >
                  {t("createToken")}
                </button>
              </HelpAction>
              <HelpAction feature="deactivate">
                <button
                  className="button secondary danger"
                  onClick={() =>
                    modal({
                      title: "deactivate",
                      info: t("confirmImpact"),
                      fields: [{ name: "reason", label: "reason" }],
                      submit: () => api("/devices/" + id, "DELETE"),
                    })
                  }
                >
                  {t("deactivate")}
                </button>
              </HelpAction>
            </div>
            <HelpAction feature="policies">
              <button
                className="button secondary"
                onClick={() =>
                  run(async () => {
                    const value = await api(
                      "/devices/" + id + "/effective-policy",
                    );
                    modal({
                      title: "effectivePolicy",
                      content: <JsonView value={value} />,
                    });
                  })
                }
              >
                {t("effectivePolicy")}
              </button>
            </HelpAction>
            <h3>{t("enrollment")}</h3>
            {requests.data?.length ? (
              requests.data
                .filter((r) => r.requested && !r.approved)
                .map((r) => (
                  <div className="list-row" key={r.id}>
                    <code>{r.csr_sha256}</code>
                    <HelpAction feature="approve">
                      <button
                        className="button secondary"
                        onClick={() =>
                          run(() =>
                            api(
                              "/devices/" +
                                id +
                                "/enrollments/" +
                                r.id +
                                "/approve",
                              "POST",
                            ),
                          )
                        }
                      >
                        {t("approve")}
                      </button>
                    </HelpAction>
                  </div>
                ))
            ) : (
              <p className="muted">{t("empty")}</p>
            )}
            <HelpAction feature="maintenance">
              <button
                className="button secondary"
                onClick={() =>
                  modal({
                    title: "maintenance",
                    info: t("confirmImpact"),
                    fields: [
                      {
                        name: "operation",
                        label: "actions",
                        type: "select",
                        options: [
                          "windows.locale",
                          "ssh.enable",
                          "firewall.apply_allowlist",
                          "system.reboot",
                        ].map((value) => ({ value, label: t(value) })),
                      },
                      {
                        name: "language",
                        label: "languageTag",
                        required: false,
                      },
                      {
                        name: "keyboard_layouts",
                        label: "keyboardLayouts",
                        value: "[]",
                        required: false,
                      },
                      {
                        name: "public_key",
                        label: "hostKey",
                        type: "textarea",
                        required: false,
                      },
                      {
                        name: "approve_disable_default_ssh_rule",
                        label: "approveSshRule",
                        type: "checkbox",
                      },
                      {
                        name: "not_before",
                        label: "schedule",
                        type: "datetime-local",
                        required: false,
                      },
                      { name: "reason", label: "reason" },
                    ],
                    submit: (v) =>
                      api("/devices/" + id + "/maintenance", "POST", {
                        ...v,
                        language: v.language || null,
                        keyboard_layouts: JSON.parse(
                          v.keyboard_layouts || "[]",
                        ),
                        public_key: v.public_key || null,
                        not_before: v.not_before
                          ? new Date(v.not_before).toISOString()
                          : null,
                      }),
                  })
                }
              >
                {t("maintenance")}
              </button>
            </HelpAction>
            <h3>{t("hardware")}</h3>
            <JsonView value={health.data?.[0]?.metrics || {}} />
            <HelpAction feature="sshConfigure">
              <button
                className="button secondary"
                onClick={() =>
                  modal({
                    title: "sshConfigure",
                    fields: [
                      { name: "host", label: "ip", value: d.network.ip },
                      { name: "username", label: "username" },
                      {
                        name: "host_public_key",
                        label: "hostKey",
                        type: "textarea",
                      },
                      {
                        name: "private_key",
                        label: "privateKey",
                        type: "textarea",
                      },
                    ],
                    submit: (v) =>
                      api("/devices/" + id + "/ssh-target", "PUT", v),
                  })
                }
              >
                {t("sshConfigure")}
              </button>
            </HelpAction>
          </>
        ) : tab === "compliance" ? (
          <>
            <p className="notice">{t("mandatoryNotice")}</p>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    {["check", "expected", "actual", "source", "status"].map(
                      (k) => (
                        <th key={k}>{t(k)}</th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody>
                  {checks.data?.checks?.map((c: any) => (
                    <tr key={c.check_id}>
                      <td>
                        <b>{t(c.check_id)}</b>
                        <small>
                          {c.error ? t(c.error) : time(c.verified_at)}
                        </small>
                      </td>
                      <td>
                        <code>{JSON.stringify(c.expected)}</code>
                      </td>
                      <td>
                        <code>{JSON.stringify(c.actual)}</code>
                      </td>
                      <td>{t(c.source)}</td>
                      <td>
                        <Badge value={c.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : tab === "permissions" ? (
          <>
            <HelpAction feature="addException">
              <button
                className="button primary"
                onClick={() =>
                  modal({
                    title: "addException",
                    fields: [
                      {
                        name: "controls",
                        label: "controls",
                        value: "disk.d.valid",
                      },
                      { name: "reason", label: "reason" },
                      {
                        name: "expires_at",
                        label: "expires",
                        type: "datetime-local",
                        required: false,
                      },
                    ],
                    submit: (v) =>
                      api("/devices/" + id + "/exceptions", "POST", {
                        ...v,
                        controls: v.controls
                          .split(",")
                          .map((c: string) => c.trim()),
                        expires_at: v.expires_at
                          ? new Date(v.expires_at).toISOString()
                          : null,
                      }),
                  })
                }
              >
                <Plus size={16} />
                {t("addException")}
              </button>
            </HelpAction>
            {exceptions.data?.map((e) => (
              <div className="list-row" key={e.id}>
                <div>
                  <b>{e.controls.map((c: string) => t(c)).join(", ")}</b>
                  <p>{e.reason}</p>
                  <small>{time(e.expires_at)}</small>
                </div>
                {!e.revoked_at && (
                  <HelpAction feature="revoke">
                    <button
                      className="button secondary danger"
                      onClick={() =>
                        run(() =>
                          api(
                            "/devices/" + id + "/exceptions/" + e.id,
                            "DELETE",
                          ),
                        )
                      }
                    >
                      {t("revoke")}
                    </button>
                  </HelpAction>
                )}
              </div>
            ))}
          </>
        ) : tab === "adm.networkTab" ? (
          <Suspense fallback={<p role="status">{t("loading")}</p>}>
            <AdmissionDevicePanel deviceId={id} />
          </Suspense>
        ) : tab === "adminCredentialTab" ? (
          <AdminCredentialPanel deviceId={id} />
        ) : tab === "history" ? (
          <HistoryTable rows={history.data || []} />
        ) : tab === "storage" ? (
          <>
            <p className="notice">{t("migrationNotice")}</p>
            <HelpAction feature="assessMigration">
              <button
                className="button secondary"
                onClick={() =>
                  run(async () => {
                    const result = await api(
                      "/devices/" + id + "/migration-assessment",
                      "POST",
                    );
                    modal({
                      title: "storage",
                      content: <JsonView value={result} />,
                    });
                  })
                }
              >
                {t("assessMigration")}
              </button>
            </HelpAction>
            <JsonView
              value={{
                volumes: d.inventory?.volumes,
                partitions: d.inventory?.partitions,
                data_locations: d.inventory?.data_locations,
                bitlocker: d.inventory?.bitlocker,
              }}
            />
          </>
        ) : (
          <JsonView
            value={
              tab === "hardware"
                ? {
                    hardware: d.inventory?.hardware,
                    os: d.inventory?.os,
                    network_adapters: d.inventory?.network_adapters,
                  }
                : tab === "users"
                  ? d.inventory?.users
                  : d.inventory?.firewall
            }
          />
        )}
      </section>
    </>
  );
}
function HistoryTable({ rows }: { rows: any[] }) {
  const t = useT();
  return rows.length ? (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {["time", "actions", "actor", "status"].map((k) => (
              <th key={k}>{t(k)}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((a, i) => (
            <tr key={a.id || i}>
              <td>{time(a.at)}</td>
              <td>{t(a.action)}</td>
              <td className="mono">{a.actor}</td>
              <td>
                <details>
                  <summary>{t("logs")}</summary>
                  <JsonView value={a.details} />
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty />
  );
}
function NetworkPage() {
  const t = useT();
  const { revision, modal, run } = useContext(WorkContext);
  const routers = useData<any[]>("/mikrotik/routers", revision);
  const aps = useData<any[]>("/mikrotik/access-points", revision);
  const subnets = useData<any[]>("/mikrotik/subnets", revision);
  const plans = useData<any[]>("/mikrotik/plans", revision);
  const options = routers.data?.map((r) => ({ value: r.id, label: r.name }));
  return (
    <>
      <Heading title="network" subtitle="supportBoundary">
        <HelpAction feature="addDeveloper">
          <button
            className="button secondary"
            onClick={() =>
              modal({
                title: "addDeveloper",
                info: t("developerNotice"),
                fields: [
                  { name: "hostname", label: "hostname", value: "Developer" },
                  { name: "mac", label: "mac" },
                  {
                    name: "subnet_id",
                    label: "profile",
                    type: "select",
                    options: subnets.data?.map((s) => ({
                      value: s.id,
                      label: s.profile + " · " + s.cidr,
                    })),
                  },
                ],
                submit: (v) => api("/mikrotik/developer-devices", "POST", v),
              })
            }
          >
            <Plus size={16} />
            {t("addDeveloper")}
          </button>
        </HelpAction>
        <HelpAction feature="addRouter">
          <button
            className="button primary"
            onClick={() =>
              modal({
                title: "addRouter",
                fields: [
                  { name: "name", label: "name" },
                  {
                    name: "base_url",
                    label: "routerAddress",
                    value: "https://",
                  },
                  { name: "username", label: "routerUser" },
                  {
                    name: "password",
                    label: "routerPassword",
                    type: "password",
                  },
                  { name: "ca_file", label: "caFile", required: false },
                ],
                submit: (v) =>
                  api("/mikrotik/routers", "POST", {
                    ...v,
                    ca_file: v.ca_file || null,
                  }),
              })
            }
          >
            <Plus size={17} />
            {t("addRouter")}
          </button>
        </HelpAction>
      </Heading>
      <div className="router-grid">
        {routers.data?.map((r) => (
          <section className="card router-card" key={r.id}>
            <div className="card-heading">
              <span className="router-icon">
                <RouterIcon />
              </span>
              <Badge value={r.status} />
            </div>
            <h2>{r.name}</h2>
            <p className="mono">{r.base_url}</p>
            <div className="router-meta">
              <span>
                RouterOS <b>{r.capabilities.version || "—"}</b>
              </span>
              <span>
                {t("ap")}{" "}
                <b>
                  {aps.data?.filter((a) => a.router_id === r.id).length || 0}
                </b>
              </span>
            </div>
            <div className="button-row">
              <HelpAction feature="discover">
                <button
                  className="button secondary"
                  onClick={() =>
                    run(async () => {
                      const result = await api(
                        "/mikrotik/routers/" + r.id + "/discover",
                        "POST",
                      );
                      modal({
                        title: "capabilities",
                        content: <JsonView value={result} />,
                      });
                    })
                  }
                >
                  <Search size={15} />
                  {t("discover")}
                </button>
              </HelpAction>
              <HelpAction feature="enableWrites">
                <button
                  className="button secondary"
                  onClick={() =>
                    modal({
                      title: "enableWrites",
                      info: t("confirmImpact"),
                      fields: [{ name: "reason", label: "reason" }],
                      submit: () =>
                        api(
                          "/mikrotik/routers/" + r.id + "/enable-writes",
                          "POST",
                        ),
                    })
                  }
                >
                  {t("enableWrites")}
                </button>
              </HelpAction>
            </div>
            <details>
              <summary>{t("capabilities")}</summary>
              <JsonView value={r.capabilities} />
            </details>
          </section>
        ))}
      </div>
      {!routers.data?.length && (
        <section className="card">
          <Empty>
            <p>{t("emptyText")}</p>
          </Empty>
        </section>
      )}
      <section className="card section-spacing">
        <div className="card-heading">
          <h2>{t("subnets")}</h2>
          <HelpAction feature="addSubnet">
            <button
              className="button secondary"
              onClick={() =>
                modal({
                  title: "addSubnet",
                  info: t("rangeConfirm"),
                  fields: [
                    {
                      name: "router_id",
                      label: "network",
                      type: "select",
                      options,
                    },
                    { name: "profile", label: "profile", value: "developer" },
                    { name: "cidr", label: "cidr" },
                    { name: "dhcp_server", label: "dhcpServer" },
                    { name: "allocation_start", label: "rangeStart" },
                    { name: "allocation_end", label: "rangeEnd" },
                    {
                      name: "confirm_range_exclusively_managed",
                      label: "rangeConfirm",
                      type: "checkbox",
                    },
                  ],
                  submit: (v) => api("/mikrotik/subnets", "POST", v),
                })
              }
            >
              <Plus size={16} />
              {t("addSubnet")}
            </button>
          </HelpAction>
        </div>
        {subnets.data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {[
                    "profile",
                    "cidr",
                    "dhcpServer",
                    "rangeStart",
                    "rangeEnd",
                  ].map((k) => (
                    <th key={k}>{t(k)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {subnets.data.map((s) => (
                  <tr key={s.id}>
                    <td>{s.profile}</td>
                    <td>{s.cidr}</td>
                    <td>{s.dhcp_server}</td>
                    <td>{s.allocation_start}</td>
                    <td>{s.allocation_end}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty />
        )}
      </section>
      <section className="card section-spacing">
        <div className="card-heading">
          <h2>{t("pendingChanges")}</h2>
        </div>
        {plans.data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {["device", "reason", "status", "actions"].map((k) => (
                    <th key={k}>{t(k)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {plans.data.map((p) => (
                  <tr key={p.id}>
                    <td className="mono">{p.device_id?.slice(0, 8) || "—"}</td>
                    <td>
                      <details>
                        <summary>{t(p.reason)}</summary>
                        <JsonView value={p.operations} />
                      </details>
                    </td>
                    <td>
                      <Badge value={p.state} />
                    </td>
                    <td>
                      {p.state === "PREVIEW" && (
                        <HelpAction feature="apply">
                          <button
                            className="button secondary"
                            onClick={() =>
                              modal({
                                title: "apply",
                                info: (
                                  <>
                                    <p>{t("confirmImpact")}</p>
                                    <JsonView value={p.operations} />
                                  </>
                                ),
                                fields: [{ name: "reason", label: "reason" }],
                                submit: () =>
                                  api(
                                    "/mikrotik/plans/" + p.id + "/apply",
                                    "POST",
                                  ),
                              })
                            }
                          >
                            {t("apply")}
                          </button>
                        </HelpAction>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty />
        )}
      </section>
    </>
  );
}
function RouterIcon() {
  return <Wifi size={24} />;
}
function Software() {
  const t = useT();
  const { revision, modal, run } = useContext(WorkContext);
  const { data, error } = useData<any[]>("/packages", revision);
  return (
    <>
      <Heading title="software" subtitle="deploymentNotice">
        <HelpAction feature="upload">
          <button
            className="button primary"
            onClick={() =>
              modal({ title: "upload", content: <UploadPackage /> })
            }
          >
            <Upload size={17} />
            {t("upload")}
          </button>
        </HelpAction>
      </Heading>
      <ErrorBox code={error} />
      <section className="card">
        {data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {["package", "kind", "size", "hash", "status", "actions"].map(
                    (k) => (
                      <th key={k}>{t(k)}</th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {data.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <div className="device-cell">
                        <span className="device-icon">
                          <Box size={18} />
                        </span>
                        <div>
                          <b>{p.name}</b>
                          <small>{p.filename}</small>
                        </div>
                      </div>
                    </td>
                    <td>{p.kind}</td>
                    <td>{(p.size / 1048576).toFixed(1)} MB</td>
                    <td>
                      <code title={p.sha256}>{p.sha256.slice(0, 16)}…</code>
                    </td>
                    <td>
                      <Badge
                        value={p.approved ? "approved" : "approvalPending"}
                      />
                    </td>
                    <td>
                      {!p.approved && (
                        <HelpAction feature="approve">
                          <button
                            className="button secondary"
                            onClick={() =>
                              modal({
                                title: "approve",
                                fields: [{ name: "reason", label: "reason" }],
                                submit: (v) =>
                                  api(
                                    "/packages/" + p.id + "/approve",
                                    "POST",
                                    v,
                                  ),
                              })
                            }
                          >
                            {t("approve")}
                          </button>
                        </HelpAction>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>
            <p>{t("deploymentNotice")}</p>
          </Empty>
        )}
      </section>
    </>
  );
}
function UploadPackage() {
  const t = useT();
  const { refresh, modal } = useContext(WorkContext);
  const [file, setFile] = useState<File | null>(null),
    [busy, setBusy] = useState(false),
    [progress, setProgress] = useState(0),
    [error, setError] = useState("");
  const [kind, setKind] = useState("msi");
  async function upload(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError("");
    const f = new FormData(e.currentTarget);
    try {
      const { createSHA256 } = await import("hash-wasm");
      const hasher = await createSHA256();
      hasher.init();
      for (let offset = 0; offset < file.size; offset += 4194304) {
        hasher.update(
          new Uint8Array(
            await file.slice(offset, offset + 4194304).arrayBuffer(),
          ),
        );
        setProgress(Math.round((offset / file.size) * 25));
      }
      const sha256 = hasher.digest();
      const descriptor = {
        name: f.get("name"),
        filename: file.name,
        sha256,
        size: file.size,
        kind,
        publisher_thumbprint: f.get("publisher"),
        architecture: f.get("architecture"),
        minimum_build: Number(f.get("minimum_build")),
        product_code: f.get("product_code") || null,
        feature_name: f.get("feature_name") || null,
        language: f.get("language") || null,
        release_version: f.get("release_version") || null,
        expected_version: f.get("expected_version") || null,
        package_identity: f.get("package_identity") || null,
        msix_name: f.get("msix_name") || null,
        driver_original_inf: f.get("driver_original_inf") || null,
        detection: f.get("detection_json")
          ? JSON.parse(String(f.get("detection_json")))
          : null,
      };
      let upload: any;
      const prior = localStorage.getItem("lantern-upload-" + sha256);
      if (prior) {
        try {
          const status = await api("/packages/uploads/" + prior);
          if (!status.completed)
            upload = {
              upload_id: prior,
              offset: status.offset,
              chunk_size: 4194304,
            };
        } catch {}
      }
      if (!upload) upload = await api("/packages/uploads", "POST", descriptor);
      if (!upload.deduplicated) {
        localStorage.setItem("lantern-upload-" + sha256, upload.upload_id);
        let offset = upload.offset;
        while (offset < file.size) {
          const chunk = file.slice(offset, offset + upload.chunk_size);
          const result = await api(
            "/packages/uploads/" + upload.upload_id + "?offset=" + offset,
            "PUT",
            chunk,
          );
          offset = result.offset;
          setProgress(25 + Math.round((offset / file.size) * 75));
        }
        await api(
          "/packages/uploads/" + upload.upload_id + "/complete",
          "POST",
        );
        localStorage.removeItem("lantern-upload-" + sha256);
      }
      refresh();
      modal(null);
    } catch (e: any) {
      setError(e.code || "request.failed");
    } finally {
      setBusy(false);
    }
  }
  return (
    <form className="modal-content" onSubmit={upload}>
      <label className="upload-zone">
        <Upload size={30} />
        <span>{file?.name || t("file")}</span>
        <input
          type="file"
          required
          disabled={busy}
          accept=".msi,.exe,.msix,.msixbundle,.cab,.msu,.ps1,.npk"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
        />
      </label>
      <div className="form-fields">
        <label>
          {t("name")}
          <input name="name" required defaultValue={file?.name} />
        </label>
        <label>
          {t("kind")}
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            {[
              "msi",
              "exe",
              "msix",
              "driver",
              "windows_update",
              "language_pack",
              "feature",
              "script",
              "agent_update",
              "routeros",
            ].map((k) => (
              <option key={k}>{k}</option>
            ))}
          </select>
        </label>
        <label>
          {t("publisher")}
          <input
            name="publisher"
            pattern="[A-Fa-f0-9]{40,64}"
            required={kind !== "routeros"}
          />
        </label>
        <label>
          {t("architecture")}
          <select name="architecture">
            {(kind === "routeros"
              ? [
                  "arm64",
                  "arm",
                  "mipsbe",
                  "mmips",
                  "tile",
                  "ppc",
                  "smips",
                  "x86",
                ]
              : ["x64", "arm64", "x86"]
            ).map((a) => (
              <option key={a}>{a}</option>
            ))}
          </select>
        </label>
        {kind === "routeros" && (
          <label>
            {t("releaseVersion")}
            <HelpButton feature="update" />
            <input
              name="release_version"
              required
              pattern="[67]\.\d+(\.\d+)?([a-z]+\d*)?"
            />
          </label>
        )}
        <label>
          {t("minimumBuild")}
          <input type="number" name="minimum_build" defaultValue={22000} />
        </label>
        {["msi", "agent_update", "exe"].includes(kind) && (
          <label>
            {t("productCode")}
            <input name="product_code" required={kind !== "exe"} />
          </label>
        )}
        {kind === "feature" && (
          <label>
            {t("featureName")}
            <input name="feature_name" required />
          </label>
        )}
        {kind === "language_pack" && (
          <label>
            {t("languageTag")}
            <input name="language" placeholder="hy-AM" />
          </label>
        )}
        {kind !== "routeros" && (
          <label>
            {t("expectedVersion")}
            <HelpButton feature="expectedVersion" />
            <input
              name="expected_version"
              required={kind === "agent_update"}
              pattern="[0-9]+(\.[0-9]+){1,3}"
            />
          </label>
        )}
        {["windows_update", "language_pack"].includes(kind) && (
          <label>
            {t("packageIdentity")}
            <HelpButton feature="packageIdentity" />
            <input name="package_identity" />
          </label>
        )}
        {kind === "msix" && (
          <label>
            {t("msixName")}
            <HelpButton feature="msixName" />
            <input name="msix_name" required />
          </label>
        )}
        {kind === "driver" && (
          <label>
            {t("driverInf")}
            <HelpButton feature="driverInf" />
            <input name="driver_original_inf" />
          </label>
        )}
        {["exe", "script"].includes(kind) && (
          <label>
            {t("detectionRule")}
            <HelpButton feature="detectionRule" />
            <textarea
              name="detection_json"
              placeholder={
                '{"kind":"registry","path":"HKLM:\\\\SOFTWARE\\\\Vendor\\\\App","value_name":"Version","expected_value":"1.0"}'
              }
            />
          </label>
        )}
      </div>
      <ErrorBox code={error} />
      {busy && (
        <div className="upload-progress">
          <progress value={progress} max={100} />
          <span>
            {t("uploading")} {progress}%
          </span>
        </div>
      )}
      <div className="modal-footer">
        <HelpAction feature="uploading">
          <button disabled={busy} className="button primary">
            <Upload size={17} />
            {busy ? t("uploading") : t("upload")}
          </button>
        </HelpAction>
      </div>
    </form>
  );
}
function Deployments() {
  const t = useT();
  const { revision, modal, run } = useContext(WorkContext);
  const { data, error } = useData<any[]>("/deployments", revision);
  const packages = useData<any[]>("/packages", revision);
  const devices = useData<{ items: Device[] }>("/devices?limit=200", revision);
  const [selected, setSelected] = useState("");
  const tasks = useData<any[]>(
    selected ? "/deployments/" + selected + "/tasks" : "/deployments",
    revision,
  );
  const create = () =>
    modal({
      title: "deploy",
      info: t("deploymentNotice"),
      fields: [
        {
          name: "package_id",
          label: "package",
          type: "select",
          options: packages.data
            ?.filter((p) => p.approved && p.kind !== "routeros")
            .map((p) => ({ value: p.id, label: p.name })),
        },
        {
          name: "device",
          label: "targets",
          type: "select",
          options: devices.data?.items
            .filter((d) => d.device_class !== "DEVELOPER")
            .map((d) => ({ value: d.id, label: d.hostname })),
        },
        { name: "all_devices", label: "allDevices", type: "checkbox" },
        {
          name: "action",
          label: "actions",
          type: "select",
          options: ["install", "update", "uninstall"].map((value) => ({
            value,
            label: t(value),
          })),
        },
        { name: "arguments", label: "arguments", value: "[]" },
        {
          name: "not_before",
          label: "schedule",
          type: "datetime-local",
          required: false,
        },
        { name: "reason", label: "reason" },
      ],
      submit: (v) =>
        api("/deployments", "POST", {
          package_id: v.package_id,
          device_ids: v.all_devices ? [] : [v.device],
          all_devices: v.all_devices,
          action: v.action,
          arguments: JSON.parse(v.arguments),
          not_before: v.not_before
            ? new Date(v.not_before).toISOString()
            : null,
          reason: v.reason,
        }),
    });
  return (
    <>
      <Heading title="deployments" subtitle="deploymentNotice">
        <HelpAction feature="deploy">
          <button className="button primary" onClick={create}>
            <Plus size={17} />
            {t("deploy")}
          </button>
        </HelpAction>
      </Heading>
      <ErrorBox code={error} />
      <section className="card">
        {data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {[
                    "package",
                    "actions",
                    "schedule",
                    "progress",
                    "actions",
                  ].map((k, i) => (
                    <th key={i}>{t(k)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.map((d) => (
                  <tr key={d.id}>
                    <td>
                      {packages.data?.find((p) => p.id === d.package_id)
                        ?.name || d.package_id}
                    </td>
                    <td>{t(d.action)}</td>
                    <td>{time(d.not_before)}</td>
                    <td>
                      <div className="count-badges">
                        {Object.entries(d.counts).map(([k, v]) => (
                          <span key={k}>
                            <Badge value={k} /> {String(v)}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <div className="button-row">
                        <HelpAction feature="logs">
                          <button
                            className="button secondary"
                            onClick={() => setSelected(d.id)}
                          >
                            {t("logs")}
                          </button>
                        </HelpAction>
                        {!d.cancelled && (
                          <button
                            className="button secondary danger"
                            onClick={() =>
                              modal({
                                title: "cancel",
                                info: t("confirmImpact"),
                                fields: [{ name: "reason", label: "reason" }],
                                submit: () =>
                                  api(
                                    "/deployments/" + d.id + "/cancel",
                                    "POST",
                                  ),
                              })
                            }
                          >
                            {t("cancel")}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty />
        )}
      </section>
      {selected && (
        <section className="card section-spacing">
          <div className="card-heading">
            <h2>{t("logs")}</h2>
          </div>
          {tasks.data?.map((task) => (
            <div className="task-row" key={task.id}>
              <div>
                <b>
                  {devices.data?.items.find((d) => d.id === task.device_id)
                    ?.hostname || task.device_id}
                </b>
                <Badge value={task.state} />
              </div>
              <JsonView value={task.result} />
              {["FAILED", "UNKNOWN", "CANCELLED"].includes(task.state) && (
                <HelpAction feature="retry">
                  <button
                    className="button secondary"
                    onClick={() =>
                      modal({
                        title: "retry",
                        info: t("confirmImpact"),
                        fields: [{ name: "reason", label: "reason" }],
                        submit: () =>
                          api(
                            "/deployment-tasks/" + task.id + "/retry",
                            "POST",
                          ),
                      })
                    }
                  >
                    {t("retry")}
                  </button>
                </HelpAction>
              )}
            </div>
          ))}
        </section>
      )}
    </>
  );
}
function TerminalPane({ session }: { session: any }) {
  const t = useT();
  const target = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let dispose = () => {};
    let stopped = false;
    import("@xterm/xterm").then(({ Terminal }) => {
      if (stopped || !target.current) return;
      const terminal = new Terminal({
        cols: 100,
        rows: 28,
        cursorBlink: true,
        fontSize: 13,
        fontFamily: "monospace",
        theme: { background: "#0c1723", foreground: "#dae7ed" },
      });
      terminal.open(target.current);
      const ws = new WebSocket(
        (location.protocol === "https:" ? "wss://" : "ws://") +
          location.host +
          session.websocket,
      );
      ws.onopen = () => {
        ws.send(session.ticket);
        terminal.focus();
      };
      ws.onmessage = (e) => terminal.write(e.data);
      ws.onclose = () => terminal.write("\r\n[closed]\r\n");
      const input = terminal.onData((text) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(text);
      });
      dispose = () => {
        input.dispose();
        ws.close();
        terminal.dispose();
      };
    });
    return () => {
      stopped = true;
      dispose();
    };
  }, [session.id]);
  return (
    <div className="modal-content">
      <p className="notice">{t("terminalNotice")}</p>
      <div className="terminal" ref={target} />
    </div>
  );
}
function Sessions() {
  const t = useT();
  const { revision, modal } = useContext(WorkContext);
  const { data, error } = useData<any[]>("/ssh/sessions", revision);
  return (
    <>
      <Heading title="sessions" subtitle="terminalNotice" />
      <ErrorBox code={error} />
      <section className="card">
        {data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {["device", "actor", "time", "status", "actions"].map((k) => (
                    <th key={k}>{t(k)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <a href={"#devices/" + s.device_id}>
                        {s.device_id.slice(0, 8)}
                      </a>
                    </td>
                    <td className="mono">{s.admin_id.slice(0, 8)}</td>
                    <td>{time(s.created_at)}</td>
                    <td>
                      <Badge value={s.state} />
                    </td>
                    <td>
                      {["ACTIVE", "AUTHORIZED"].includes(s.state) && (
                        <HelpAction feature="terminate">
                          <button
                            className="button secondary danger"
                            onClick={() =>
                              modal({
                                title: "terminate",
                                info: t("confirmImpact"),
                                fields: [{ name: "reason", label: "reason" }],
                                submit: () =>
                                  api(
                                    "/ssh/sessions/" + s.id + "/terminate",
                                    "POST",
                                  ),
                              })
                            }
                          >
                            {t("terminate")}
                          </button>
                        </HelpAction>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty />
        )}
      </section>
    </>
  );
}
function Alerts() {
  const t = useT();
  const { revision, run } = useContext(WorkContext);
  const { data, error } = useData<any[]>("/alerts", revision);
  return (
    <>
      <Heading title="alerts" subtitle="mandatoryNotice" />
      <ErrorBox code={error} />
      <section className="card">
        {data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {["severity", "device", "reason", "time", "actions"].map(
                    (k) => (
                      <th key={k}>{t(k)}</th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {data.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <Badge value={a.severity} />
                    </td>
                    <td>
                      {a.device_id ? (
                        <a href={"#devices/" + a.device_id}>
                          {a.device_id.slice(0, 8)}
                        </a>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      <b>{t(a.code)}</b>
                      <details>
                        <summary>{t("logs")}</summary>
                        <JsonView value={a.details} />
                      </details>
                    </td>
                    <td>{time(a.at)}</td>
                    <td>
                      {!a.acknowledged_by ? (
                        <HelpAction feature="acknowledge">
                          <button
                            className="button secondary"
                            onClick={() =>
                              run(() =>
                                api("/alerts/" + a.id + "/acknowledge", "POST"),
                              )
                            }
                          >
                            {t("acknowledge")}
                          </button>
                        </HelpAction>
                      ) : (
                        <CheckCheck size={19} />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="noAlerts" />
        )}
      </section>
    </>
  );
}
function Audit() {
  const { revision } = useContext(WorkContext);
  const { data, error } = useData<any[]>("/audit", revision);
  return (
    <>
      <Heading title="audit" />
      <ErrorBox code={error} />
      <section className="card">
        <HistoryTable rows={data || []} />
      </section>
    </>
  );
}
function SettingsPage() {
  const t = useT();
  const { identity, modal, run, revision } = useContext(WorkContext);
  const { data } = useData("/dashboard", revision);
  return (
    <>
      <Heading title="settings" />
      <section className="card settings-card">
        <div className="settings-icon">
          <LockKeyhole size={24} />
        </div>
        <h2>{t("mfaTitle")}</h2>
        <p>{t("mfaDescription")}</p>
        <div className="button-row">
          <HelpAction feature="mfaSetup">
            <button
              className="button primary"
              onClick={() =>
                run(async () => {
                  const result = await api("/auth/mfa/setup", "POST");
                  modal({
                    title: "mfaTitle",
                    info: (
                      <>
                        <p>{t("mfaUri")}</p>
                        <pre className="secret">{result.uri}</pre>
                      </>
                    ),
                    fields: [{ name: "code", label: "totp" }],
                    submit: (v) =>
                      api("/auth/mfa/confirm", "POST", {
                        challenge: result.challenge,
                        code: v.code,
                      }),
                  });
                })
              }
            >
              {t("mfaSetup")}
            </button>
          </HelpAction>
          <HelpAction feature="mfaRefresh">
            <button
              className="button secondary"
              onClick={() =>
                modal({
                  title: "mfaRefresh",
                  fields: [{ name: "code", label: "totp" }],
                  submit: (v) => api("/auth/mfa/reauthenticate", "POST", v),
                })
              }
            >
              {t("mfaRefresh")}
            </button>
          </HelpAction>
        </div>
      </section>
      <section className="card settings-card">
        <h2>{t("language")}</h2>
        <LanguageSelector />
      </section>
      <section className="card settings-card">
        <h2>{t("lowResource")}</h2>
        <p>{t("lowResourceText")}</p>
        <JsonView
          value={{
            low_resource_mode: data?.low_resource_mode,
            poll_seconds: data?.poll_seconds,
            deployment_concurrency: data?.deployment_concurrency,
            features: data?.features,
          }}
        />
      </section>
    </>
  );
}
