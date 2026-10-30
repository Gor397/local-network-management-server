import { useContext, useState, type ReactNode } from "react";
import {
  Activity,
  ArrowRight,
  Check,
  Download,
  Edit,
  Network,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  Trash2,
  Wifi,
} from "lucide-react";
import { WorkContext, type Field } from "../context";
import { api } from "../api/client";
import { useData } from "../hooks/useData";
import { useT } from "../i18n";
import { HelpAction, HelpButton } from "../components/Help";
import type { HelpId } from "../help/catalog";
import { NetworkExplorer } from "./NetworkExplorer";
import { AdmissionPage } from "./AdmissionPage";

const fmt = (v: any) =>
  v
    ? new Date(v.endsWith?.("Z") ? v : v + "Z").toLocaleString(
        document.documentElement.lang || "hy-AM",
      )
    : "—";
function State({ value }: { value: string }) {
  const t = useT();
  return (
    <span className={"badge " + value.toLowerCase()}>
      <i />
      {t(value)}
    </span>
  );
}
function Json({ value }: { value: any }) {
  return <pre className="json-view">{JSON.stringify(value, null, 2)}</pre>;
}
function Page({
  title,
  help,
  children,
  actions,
}: {
  title: string;
  help: HelpId;
  children: ReactNode;
  actions?: ReactNode;
}) {
  const t = useT();
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">Suro / {t("workspace")}</span>
          <h1>
            {t(title)} <HelpButton id={help} />
          </h1>
        </div>
        <div className="heading-actions">{actions}</div>
      </div>
      {children}
    </>
  );
}
function Panel({ title, children }: { title?: string; children: ReactNode }) {
  const t = useT();
  return (
    <section className="card section-spacing">
      {title && (
        <div className="card-heading">
          <h2>{t(title)}</h2>
        </div>
      )}
      <div className="suro-panel">{children}</div>
    </section>
  );
}
function DataError({ error }: { error: string }) {
  const t = useT();
  return error ? (
    <div className="error" role="alert">
      {t("error")}: {t(error)}
    </div>
  ) : null;
}
function useTools() {
  return { ...useContext(WorkContext), t: useT() };
}
const reason: Field = { name: "reason", label: "reason" };

export function SuroPages({ page, id }: { page: string; id?: string }) {
  if (page === "admission") return <AdmissionPage />;
  if (page === "explorer")
    return (
      <Page title="explorer" help="network-explorer">
        <NetworkExplorer />
      </Page>
    );
  if (page === "connected-clients") return <ConnectedClients />;
  if (page === "network-inventory") return <NetworkInventory />;
  if (page === "owners") return <Owners />;
  if (page === "device-groups" || page === "ap-groups")
    return <Groups network={page === "ap-groups"} />;
  if (page === "access-points") return <AccessPoints id={id} />;
  if (page === "network-overview") return <NetworkOverview />;
  if (page === "incidents" || page === "diagnostics")
    return <Incidents diagnostics={page === "diagnostics"} />;
  if (page === "topology") return <Topology />;
  if (page === "maintenance-jobs") return <Jobs />;
  if (page === "recovery-settings") return <Recovery />;
  if (page === "administrators") return <Administrators />;
  if (page === "monitoring-settings") return <MonitoringSettings />;
  if (page === "policy-layers") return <PolicyLayers />;
  return <SystemHealth />;
}

function NetworkOverview() {
  const { t, revision } = useTools(),
    summary = useData("/network/overview", revision),
    routers = useData<any[]>("/mikrotik/routers", revision);
  return (
    <Page title="network-overview" help="ap-inventory">
      <DataError error={summary.error} />
      <div className="stats">
        {[
          "total",
          "online",
          "offline",
          "unhealthy",
          "connected_clients",
          "incidents",
        ].map((k) => (
          <div className="stat" key={k}>
            <div className="stat-top">
              {t(k)}
              <Wifi size={18} />
            </div>
            <strong>{summary.data?.[k] ?? "—"}</strong>
          </div>
        ))}
      </div>
      <Panel title="ap-groups">
        <div className="group-cards">
          {summary.data?.groups?.map((g: any) => (
            <a className="group-card" key={g.id} href="#ap-groups">
              <Network />
              <h3>{g.name}</h3>
              <p>
                {g.online} {t("online")} / {g.offline} {t("offline")}
              </p>
            </a>
          ))}
        </div>
      </Panel>
      <Panel title="access-points">
        <RouterTable rows={routers.data || []} />
      </Panel>
    </Page>
  );
}
function RouterTable({ rows }: { rows: any[] }) {
  const t = useT();
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {[
              "name",
              "model",
              "version",
              "role",
              "status",
              "cpu",
              "memory",
              "clients",
              "lastSync",
            ].map((k) => (
              <th key={k}>{t(k)}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>
                <a href={"#access-points/" + r.id}>
                  <b>{r.name}</b>
                </a>
                <small>
                  {r.controller_id
                    ? `${t("managedBy")} ${r.controller_name}`
                    : r.base_url}
                </small>
              </td>
              <td>{r.inventory?.model || t("unavailable")}</td>
              <td>{r.inventory?.version || r.capabilities?.version || "—"}</td>
              <td>{t(r.role)}</td>
              <td>
                <State value={r.status} />
              </td>
              <td>
                {r.health?.cpu_percent ?? "—"}
                {r.health?.cpu_percent != null ? "%" : ""}
              </td>
              <td>
                {r.health?.memory_percent ?? "—"}
                {r.health?.memory_percent != null ? "%" : ""}
              </td>
              <td>{r.health?.client_count ?? "—"}</td>
              <td>{fmt(r.last_inventory)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function usePermanentDelete() {
  const { t, modal } = useTools();
  return (router: { id: string; name: string }) =>
    modal({
      title: "deletePermanently",
      info: (
        <p className="notice">
          {t("deletePermanentlyNotice")} <b>{router.name}</b>
        </p>
      ),
      fields: [{ name: "confirm_name", label: "typeNameToConfirm" }],
      submit: async (v) => {
        await api(
          `/mikrotik/routers/${router.id}/permanent?confirm_name=${encodeURIComponent(v.confirm_name)}`,
          "DELETE",
        );
        location.hash = "#access-points";
      },
    });
}

function ArchivedRouters() {
  const { t, revision } = useTools(),
    archived = useData<any[]>("/mikrotik/routers/archived", revision),
    remove = usePermanentDelete();
  if (!archived.data?.length) return null;
  return (
    <Panel title="archivedDevices">
      <div className="table-wrap">
        <table>
          <tbody>
            {archived.data.map((r) => (
              <tr key={r.id}>
                <td>
                  <b>{r.name}</b>
                  <small>{r.base_url}</small>
                </td>
                <td>{t(r.role)}</td>
                <td>
                  <button
                    className="button secondary danger"
                    onClick={() => remove(r)}
                  >
                    <Trash2 size={14} />
                    {t("deletePermanently")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function AccessPoints({ id }: { id?: string }) {
  const { t, revision, modal, run } = useTools(),
    packages = useData<any[]>("/packages", revision),
    routers = useData<any[]>("/mikrotik/routers", revision),
    telemetry = useData<any[]>(
      id ? `/mikrotik/routers/${id}/telemetry` : "/mikrotik/access-points",
      revision,
    ),
    inventory = useData(
      id ? `/mikrotik/routers/${id}/inventory` : "/network/overview",
      revision,
    ),
    backups = useData<any[]>(
      id ? `/mikrotik/routers/${id}/backups` : "/mikrotik/groups",
      revision,
    );
  const [tab, setTab] = useState("overview");
  const remove = usePermanentDelete();
  const r = routers.data?.find((x) => x.id === id);
  const add = () =>
    modal({
      title: "addRouter",
      info: t("apRegistrationNotice"),
      fields: [
        { name: "name", label: "name" },
        { name: "base_url", label: "routerAddress", value: "https://" },
        { name: "username", label: "routerUser" },
        { name: "password", label: "routerPassword", type: "password" },
        { name: "ca_file", label: "caFile", required: false },
        {
          name: "transport",
          label: "transport",
          type: "select",
          options: ["REST", "API_SSL", "API"].map((value) => ({
            value,
            label: t(value),
          })),
        },
        {
          name: "role",
          label: "role",
          type: "select",
          options: ["ACCESS_POINT", "ROUTER", "GATEWAY", "CONTROLLER"].map(
            (value) => ({ value, label: t(value) }),
          ),
        },
        { name: "protected", label: "protected", type: "checkbox" },
      ],
      submit: (v) =>
        api("/mikrotik/routers", "POST", { ...v, ca_file: v.ca_file || null }),
    });
  if (!id)
    return (
      <Page
        title="access-points"
        help="ap-inventory"
        actions={
          <HelpAction feature="addRouter">
            <button className="button primary" onClick={add}>
              <Plus size={16} />
              {t("addRouter")}
            </button>
          </HelpAction>
        }
      >
        <DataError error={routers.error} />
        <Panel>
          <RouterTable rows={routers.data || []} />
          {!routers.data?.length && <p>{t("empty")}</p>}
        </Panel>
        <ArchivedRouters />
      </Page>
    );
  return (
    <Page
      title="access-points"
      help="ap-inventory"
      actions={
        <>
          <a className="button secondary" href="#access-points">
            {t("back")}
          </a>
          <HelpAction feature="discover">
            <button
              className="button secondary"
              disabled={!!r?.controller_id}
              title={r?.controller_id ? t("managedByNotice") : undefined}
              onClick={() =>
                run(() => api(`/mikrotik/routers/${id}/discover`, "POST"))
              }
            >
              <RefreshCw size={16} />
              {t("discover")}
            </button>
          </HelpAction>
          <HelpAction feature="reboot">
            <button
              className="button primary"
              onClick={() => openOperation(modal, t, [id], "reboot")}
            >
              {t("reboot")}
            </button>
          </HelpAction>
        </>
      }
    >
      <DataError error={routers.error} />
      <Panel title={r?.name}>
        <div className="detail-grid">
          {[
            ["model", r?.inventory?.model],
            ["serial", r?.inventory?.serial_number],
            ["version", r?.inventory?.version],
            ["uptime", r?.health?.uptime_seconds],
            ["temperature", r?.health?.temperature],
            ["voltage", r?.health?.voltage],
            ["power", r?.health?.power],
            ["lastReboot", fmt(r?.last_reboot)],
          ].map(([k, v]) => (
            <div key={k}>
              <span>{t(k)}</span>
              <strong>{v ?? t("unavailable")}</strong>
            </div>
          ))}
        </div>
        <div className="button-row">
          {!r?.write_enabled && (
            <HelpAction feature="enableWrites">
              <button
                className="button secondary"
                onClick={() =>
                  modal({
                    title: "enableWrites",
                    info: t("confirmImpact"),
                    fields: [reason],
                    submit: () =>
                      api(`/mikrotik/routers/${id}/enable-writes`, "POST"),
                  })
                }
              >
                {t("enableWrites")}
              </button>
            </HelpAction>
          )}
          {[
            "wireless",
            "snapshot",
            "binary_backup",
            "diagnostics",
            "upgrade",
            "binary_restore",
            "identity",
          ].map((op) => (
            <HelpAction
              key={op}
              feature={
                op === "snapshot" || op === "binary_backup" ? "backup" : op
              }
            >
              <button
                className="button secondary"
                onClick={() =>
                  openOperation(
                    modal,
                    t,
                    [id],
                    op,
                    {},
                    undefined,
                    packages.data || [],
                  )
                }
              >
                {t(op)}
              </button>
            </HelpAction>
          ))}
          <HelpAction feature="secrets">
            <button
              className="button secondary"
              onClick={() =>
                modal({
                  title: "editDevice",
                  fields: [
                    { name: "name", label: "name", value: r?.name },
                    {
                      name: "role",
                      label: "role",
                      type: "select",
                      value: r?.role,
                      options: [
                        "ACCESS_POINT",
                        "ROUTER",
                        "GATEWAY",
                        "CONTROLLER",
                      ].map((value) => ({ value, label: t(value) })),
                    },
                    {
                      name: "protected",
                      label: "protected",
                      type: "checkbox",
                      value: r?.protected,
                    },
                    {
                      name: "ssh_host_key",
                      label: "hostKey",
                      type: "textarea",
                      required: false,
                    },
                  ],
                  submit: ({ ssh_host_key, ...metadata }) =>
                    api(`/mikrotik/routers/${id}`, "PATCH", {
                      ...metadata,
                      ...(ssh_host_key ? { ssh_host_key } : {}),
                    }),
                })
              }
            >
              {t("editDevice")}
            </button>
          </HelpAction>
          <HelpAction feature="backups">
            <button
              className="button secondary danger"
              onClick={() =>
                modal({
                  title: "archive",
                  info: t("archiveNotice"),
                  fields: [reason],
                  submit: () => api(`/mikrotik/routers/${id}`, "DELETE"),
                })
              }
            >
              {t("archive")}
            </button>
          </HelpAction>
          {r && (
            <button
              className="button secondary danger"
              onClick={() => remove(r)}
            >
              <Trash2 size={14} />
              {t("deletePermanently")}
            </button>
          )}
        </div>
      </Panel>
      <div className="tabs">
        {[
          "overview",
          "interfaces",
          "clients",
          "configuration",
          "logs",
          "backups",
        ].map((key) => (
          <button
            className={tab === key ? "active" : ""}
            key={key}
            onClick={() => setTab(key)}
          >
            {t(key)}
          </button>
        ))}
      </div>
      <Panel>
        {tab === "overview" ? (
          <Json value={r?.health} />
        ) : tab === "interfaces" ? (
          <Json value={r?.health?.interfaces || r?.inventory?.interfaces} />
        ) : tab === "clients" ? (
          <Json value={telemetry.data?.[0]?.clients || []} />
        ) : tab === "configuration" ? (
          <Json value={inventory.data} />
        ) : tab === "logs" ? (
          <Json value={r?.inventory?.logs} />
        ) : (
          <div>
            {backups.data?.map((b) => (
              <div className="list-row" key={b.id}>
                <span>
                  {b.kind} · {fmt(b.at)}
                  <small>{b.id}</small>
                </span>
                <HelpAction feature="restore">
                  <button
                    className="button secondary"
                    onClick={() =>
                      openOperation(
                        modal,
                        t,
                        [id],
                        b.kind === "BINARY"
                          ? "binary_restore"
                          : "restore_fields",
                        { backup_id: b.id },
                      )
                    }
                  >
                    {t("restore")}
                  </button>
                </HelpAction>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </Page>
  );
}
function openOperation(
  modal: any,
  t: (key: string) => string,
  ids: string[],
  operation: string,
  preset: any = {},
  groupId?: string,
  packages: any[] = [],
) {
  const fields: Field[] = [
    reason,
    { name: "independent_paths", label: "independentPaths", required: false },
    {
      name: "not_before",
      label: "schedule",
      type: "datetime-local",
      required: false,
    },
    {
      name: "window_end",
      label: "windowEnd",
      type: "datetime-local",
      required: false,
    },
    { name: "batch_size", label: "batchSize", type: "number", value: 1 },
    {
      name: "stop_on_failure",
      label: "stopOnFailure",
      type: "checkbox",
      value: true,
    },
  ];
  if (operation === "wireless")
    fields.unshift(
      {
        name: "stack",
        label: "stack",
        type: "select",
        options: ["wifi", "wireless", "capsman"].map((value) => ({
          value,
          label: value,
        })),
      },
      { name: "interface", label: "interface", value: "wifi1" },
      { name: "ssid", label: "ssid", required: false },
      {
        name: "disabled",
        label: "disableWireless",
        type: "select",
        value: "unchanged",
        options: [
          { value: "unchanged", label: t("keepCurrent") },
          { value: "true", label: t("disabled") },
          { value: "false", label: t("enabled") },
        ],
      },
      { name: "frequency", label: "frequency", required: false },
      { name: "channel_width", label: "channelWidth", required: false },
    );
  if (operation === "identity") fields.unshift({ name: "name", label: "name" });
  if (operation === "upgrade")
    fields.unshift({
      name: "package_id",
      label: "package",
      type: "select",
      options: packages
        .filter((p) => p.approved && p.kind === "routeros")
        .map((p) => ({
          value: p.id,
          label: `${p.name} · ${p.metadata?.release_version || ""} · ${p.metadata?.architecture || ""}`,
        })),
    });
  if (operation === "binary_restore" && !preset.backup_id)
    fields.unshift({ name: "backup_id", label: "backupId" });
  if (operation === "diagnostics")
    fields.unshift({
      name: "address",
      label: "diagnosticAddress",
      required: false,
    });
  modal({
    title: "operationPreview",
    info: t("batchSafetyNotice"),
    fields,
    submit: async (v: any) => {
      const parameters = {
        ...preset,
        independent_management_router_ids: (v.independent_paths || "")
          .split(",")
          .map((i: string) => i.trim())
          .filter(Boolean),
      };
      for (const k of [
        "stack",
        "interface",
        "ssid",
        "frequency",
        "channel_width",
        "name",
        "package_id",
        "backup_id",
        "address",
      ])
        if (v[k] !== undefined && v[k] !== "") parameters[k] = v[k];
      if (v.disabled === "true" || v.disabled === "false")
        parameters.disabled = v.disabled === "true";
      const result = await api("/network/operations/preview", "POST", {
        router_ids: ids,
        group_id: groupId || null,
        operation,
        parameters,
        reason: v.reason,
        batch_size: v.batch_size,
        stop_on_failure: v.stop_on_failure,
        not_before: v.not_before ? new Date(v.not_before).toISOString() : null,
        window_end: v.window_end ? new Date(v.window_end).toISOString() : null,
      });
      modal({
        title: "operationPreview",
        content: <BatchReview id={result.id} />,
      });
    },
  });
}
function BatchReview({ id }: { id: string }) {
  const { t, revision, run } = useTools(),
    { data, error, reload } = useData("/network/operations/" + id, revision),
    [confirmed, setConfirmed] = useState(false),
    [oob, setOob] = useState(false),
    [names, setNames] = useState("");
  return (
    <div className="modal-content">
      <DataError error={error} />
      <p className="notice">
        {t("batchSafetyNotice")} <HelpButton id="ap-groups" />
      </p>
      <State value={data?.state || "PENDING"} />
      {data?.targets?.map((target: any) => (
        <section className="operation-target" key={target.id}>
          <h3>{target.preview?.router_name || target.device_id}</h3>
          <State value={target.state} />
          <p>{t(target.preview?.impact || "network.read_only")}</p>
          {target.preview?.compatible === false && (
            <DataError error={target.preview.code} />
          )}
          <Json value={target.preview?.changes || target.preview} />
          <Json value={target.result} />
        </section>
      ))}
      {data?.state === "PREVIEW" && (
        <>
          <label className="checkbox">
            {t("confirmTargets")}
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
          </label>
          <label>
            {t("protectedNames")}
            <HelpButton id="reboot" />
            <input value={names} onChange={(e) => setNames(e.target.value)} />
          </label>
          <label className="checkbox">
            {t("outOfBandConfirmed")}
            <input
              type="checkbox"
              checked={oob}
              onChange={(e) => setOob(e.target.checked)}
            />
          </label>
          <HelpAction feature="apply">
            <button
              disabled={!confirmed}
              className="button primary"
              onClick={() =>
                run(async () => {
                  await api("/network/operations/" + id + "/approve", "POST", {
                    confirm: confirmed,
                    confirmed_protected: names
                      .split(",")
                      .map((n) => n.trim())
                      .filter(Boolean),
                    out_of_band_confirmed: oob,
                  });
                  reload();
                })
              }
            >
              {t("approve")}
            </button>
          </HelpAction>
        </>
      )}
      <button className="button secondary" onClick={reload}>
        {t("refresh")}
      </button>
    </div>
  );
}

function Groups({ network }: { network: boolean }) {
  const { t, revision, modal, run } = useTools(),
    base = network ? "/mikrotik/groups" : "/groups",
    { data, error } = useData<any[]>(base, revision),
    policies = useData<any[]>("/policies", revision),
    packages = useData<any[]>("/packages", revision);
  const edit = (group?: any) =>
    modal({
      title: network ? "ap-groups" : "device-groups",
      content: <GroupEditor network={network} group={group} />,
    });
  const groupAction = (g: any) =>
    modal({
      title: "assignPolicy",
      fields: [
        {
          name: "policy",
          label: "policy",
          type: "select",
          options: policies.data
            ?.filter((p) => p.active_version_id)
            .map((p) => ({ value: JSON.stringify(p), label: p.name })),
        },
        reason,
      ],
      submit: (v) => {
        const p = JSON.parse(v.policy);
        return api(`/groups/${g.id}/operations`, "POST", {
          operation: "POLICY",
          parameters: { policy_id: p.id, version_id: p.active_version_id },
          reason: v.reason,
        });
      },
    });
  return (
    <Page
      title={network ? "ap-groups" : "device-groups"}
      help={network ? "ap-groups" : "device-groups"}
      actions={
        <HelpAction feature={network ? "apGroups" : "deviceGroups"}>
          <button className="button primary" onClick={() => edit()}>
            <Plus size={16} />
            {t("createGroup")}
          </button>
        </HelpAction>
      }
    >
      <DataError error={error} />
      <div className="group-cards">
        {data?.map((g) => (
          <section className="card group-card" key={g.id}>
            <h2>{g.name}</h2>
            <p>{g.description}</p>
            <strong>
              {(network ? g.router_ids : g.device_ids)?.length} {t("members")}
            </strong>
            {network && (
              <p>
                {g.online} {t("online")} · {g.offline} {t("offline")}
              </p>
            )}
            <div className="button-row">
              <HelpAction feature="editDevice">
                <button className="button secondary" onClick={() => edit(g)}>
                  {t("editDevice")}
                </button>
              </HelpAction>
              {network ? (
                <>
                  <HelpAction feature="reboot">
                    <button
                      className="button secondary"
                      onClick={() =>
                        openOperation(modal, t, [], "reboot", {}, g.id)
                      }
                    >
                      {t("reboot")}
                    </button>
                  </HelpAction>
                  <HelpAction feature="wireless">
                    <button
                      className="button secondary"
                      onClick={() =>
                        openOperation(modal, t, [], "template", {}, g.id)
                      }
                    >
                      {t("applyTemplate")}
                    </button>
                  </HelpAction>
                  <HelpAction feature="apGroups">
                    <select
                      aria-label={t("actions")}
                      value=""
                      onChange={(e) => {
                        if (e.target.value)
                          openOperation(
                            modal,
                            t,
                            [],
                            e.target.value,
                            {},
                            g.id,
                            packages.data || [],
                          );
                      }}
                    >
                      <option value="">{t("actions")}</option>
                      {[
                        "wireless",
                        "snapshot",
                        "binary_backup",
                        "upgrade",
                        "diagnostics",
                        "identity",
                      ].map((op) => (
                        <option key={op} value={op}>
                          {t(op)}
                        </option>
                      ))}
                    </select>
                  </HelpAction>
                </>
              ) : (
                <>
                  <HelpAction feature="recheck">
                    <button
                      className="button secondary"
                      onClick={() =>
                        run(() =>
                          api(`/groups/${g.id}/operations`, "POST", {
                            operation: "SYNC",
                            reason: "Requested group compliance scan",
                          }),
                        )
                      }
                    >
                      {t("recheck")}
                    </button>
                  </HelpAction>
                  <HelpAction feature="assignPolicy">
                    <button
                      className="button secondary"
                      onClick={() => groupAction(g)}
                    >
                      {t("assignPolicy")}
                    </button>
                  </HelpAction>
                  <HelpAction feature="deploy">
                    <button
                      className="button secondary"
                      onClick={() =>
                        modal({
                          title: "deploy",
                          content: <GroupDeployment group={g} />,
                        })
                      }
                    >
                      {t("deploy")}
                    </button>
                  </HelpAction>
                  <HelpAction feature="maintenance">
                    <button
                      className="button secondary"
                      onClick={() =>
                        modal({
                          title: "maintenance",
                          fields: [
                            {
                              name: "operation",
                              label: "actions",
                              type: "select",
                              options: [
                                "windows.locale",
                                "ssh.enable",
                                "system.reboot",
                                "firewall.apply_allowlist",
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
                              name: "not_before",
                              label: "schedule",
                              type: "datetime-local",
                              required: false,
                            },
                            reason,
                          ],
                          submit: (v) =>
                            api(`/groups/${g.id}/operations`, "POST", {
                              operation: "MAINTENANCE",
                              reason: v.reason,
                              parameters: {
                                operation: v.operation,
                                language: v.language || null,
                                keyboard_layouts: JSON.parse(
                                  v.keyboard_layouts || "[]",
                                ),
                                public_key: v.public_key || null,
                                not_before: v.not_before
                                  ? new Date(v.not_before).toISOString()
                                  : null,
                              },
                            }),
                        })
                      }
                    >
                      {t("maintenance")}
                    </button>
                  </HelpAction>
                </>
              )}
              <HelpAction feature="deviceGroups">
                <button
                  className="button secondary danger"
                  onClick={() =>
                    modal({
                      title: "deleteGroup",
                      info: t("confirmImpact"),
                      fields: [reason],
                      submit: () => api(base + "/" + g.id, "DELETE"),
                    })
                  }
                >
                  <Trash2 size={14} />
                  {t("deleteGroup")}
                </button>
              </HelpAction>
            </div>
          </section>
        ))}
      </div>
      {!data?.length && (
        <Panel>
          <p>{t("empty")}</p>
        </Panel>
      )}
    </Page>
  );
}
function GroupEditor({ network, group }: { network: boolean; group?: any }) {
  const [query, setQuery] = useState(""),
    [memberPage, setMemberPage] = useState(0);
  const { t, revision, refresh, modal } = useTools(),
    members = useData<any>(
      network
        ? "/mikrotik/routers"
        : `/devices?limit=50&offset=${memberPage * 50}&q=${encodeURIComponent(query)}`,
      revision,
    ),
    [name, setName] = useState(group?.name || ""),
    [description, setDescription] = useState(group?.description || ""),
    [selected, setSelected] = useState<string[]>(
      group?.[network ? "router_ids" : "device_ids"] || [],
    ),
    [error, setError] = useState(""),
    [ssid, setSsid] = useState(group?.template?.ssid || ""),
    [stack, setStack] = useState(group?.template?.stack || "wifi"),
    [iface, setIface] = useState(group?.template?.interface || "wifi1");
  const rows = network
    ? (members.data || []).filter((r: any) =>
        [r.name, r.base_url, r.inventory?.model, r.controller_name]
          .join(" ")
          .toLowerCase()
          .includes(query.toLowerCase()),
      )
    : members.data?.items || [];
  async function save() {
    try {
      const value = {
        name,
        description,
        [network ? "router_ids" : "device_ids"]: selected,
        ...(network
          ? {
              template: ssid
                ? { ...group?.template, ssid, stack, interface: iface }
                : {},
            }
          : {}),
      };
      await api(
        (network ? "/mikrotik/groups" : "/groups") +
          (group ? "/" + group.id : ""),
        group ? "PUT" : "POST",
        value,
      );
      refresh();
      modal(null);
    } catch (e: any) {
      setError(e.code || "request.failed");
    }
  }
  return (
    <div className="modal-content">
      <label>
        {t("name")}
        <input value={name} onChange={(e) => setName(e.target.value)} />
      </label>
      <label>
        {t("description")}
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </label>
      <label>
        {t("members")}
        <HelpButton id={network ? "ap-groups" : "device-groups"} />
      </label>
      <input
        aria-label={t("search")}
        placeholder={t("search")}
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setMemberPage(0);
        }}
      />
      <div className="member-list">
        {rows.map((d: any) => (
          <label className="member-option" key={d.id}>
            <input
              type="checkbox"
              checked={selected.includes(d.id)}
              onChange={(e) =>
                setSelected(
                  e.target.checked
                    ? [...selected, d.id]
                    : selected.filter((i) => i !== d.id),
                )
              }
            />
            <span>
              {d.name || d.hostname}
              <small>{d.base_url || d.primary_mac}</small>
            </span>
          </label>
        ))}
      </div>
      {!network && (
        <div className="pagination">
          <span>
            {selected.length} {t("members")}
          </span>
          <button
            className="button secondary"
            disabled={!memberPage}
            onClick={() => setMemberPage((p) => p - 1)}
          >
            {t("previous")}
          </button>
          <button
            className="button secondary"
            disabled={(memberPage + 1) * 50 >= (members.data?.total || 0)}
            onClick={() => setMemberPage((p) => p + 1)}
          >
            {t("next")}
          </button>
        </div>
      )}
      {network && (
        <>
          <h3>
            {t("groupTemplate")} <HelpButton id="wireless" />
          </h3>
          <label>
            {t("stack")}
            <select value={stack} onChange={(e) => setStack(e.target.value)}>
              <option>wifi</option>
              <option>wireless</option>
              <option>capsman</option>
            </select>
          </label>
          <label>
            {t("interface")}
            <input value={iface} onChange={(e) => setIface(e.target.value)} />
          </label>
          <label>
            {t("ssid")}
            <input
              maxLength={32}
              value={ssid}
              onChange={(e) => setSsid(e.target.value)}
            />
          </label>
          <p className="notice">{t("templateStaged")}</p>
        </>
      )}
      <DataError error={error} />
      <HelpAction feature="save">
        <button
          className="button primary"
          disabled={!name.trim()}
          onClick={save}
        >
          {t("save")}
        </button>
      </HelpAction>
    </div>
  );
}
function GroupDeployment({ group }: { group: any }) {
  const { t, revision, run, modal } = useTools(),
    packages = useData<any[]>("/packages", revision),
    [packageId, setPackageId] = useState(""),
    [why, setWhy] = useState(""),
    [action, setAction] = useState("install");
  return (
    <div className="modal-content">
      <p>
        {group.name} · {group.device_ids.length} {t("targets")}
      </p>
      <HelpButton id="deployments" />
      <label>
        {t("package")}
        <select
          value={packageId}
          onChange={(e) => setPackageId(e.target.value)}
        >
          <option value="">—</option>
          {packages.data
            ?.filter((p) => p.approved && p.kind !== "routeros")
            .map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
        </select>
      </label>
      <label>
        {t("actions")}
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          {["install", "update", "uninstall"].map((a) => (
            <option key={a} value={a}>
              {t(a)}
            </option>
          ))}
        </select>
      </label>
      <label>
        {t("reason")}
        <textarea value={why} onChange={(e) => setWhy(e.target.value)} />
      </label>
      <p className="notice">{t("deploymentNotice")}</p>
      <HelpAction feature="deploy">
        <button
          className="button primary"
          disabled={!packageId || why.length < 5}
          onClick={() =>
            run(async () => {
              await api("/deployments", "POST", {
                package_id: packageId,
                group_ids: [group.id],
                action,
                reason: why,
              });
              modal(null);
            })
          }
        >
          {t("deploy")}
        </button>
      </HelpAction>
    </div>
  );
}
function Owners() {
  const { t, revision, modal } = useTools(),
    [q, setQ] = useState(""),
    [rank, setRank] = useState(""),
    [page, setPage] = useState(0),
    { data, error } = useData(
      `/devices?limit=25&offset=${page * 25}&q=${encodeURIComponent(q)}${rank ? "&owner_rank=" + encodeURIComponent(rank) : ""}`,
      revision,
    );
  const edit = (d: any) =>
    modal({
      title: "assignOwner",
      info: t("ownerSeparation"),
      fields: [
        { name: "full_name", label: "fullName", value: d.owner_name || "" },
        {
          name: "military_rank",
          label: "militaryRank",
          value: d.owner_rank || "",
          required: false,
        },
        {
          name: "windows_account",
          label: "windowsAccount",
          value: d.owner_account || d.last_user_account || "",
          required: false,
        },
        {
          name: "verified",
          label: "identityVerified",
          type: "checkbox",
          value: d.owner_verified,
        },
        reason,
      ],
      submit: (v) =>
        api(`/devices/${d.id}/owner`, "PUT", {
          ...v,
          military_rank: v.military_rank || null,
          windows_account: v.windows_account || null,
        }),
    });
  return (
    <Page
      title="owners"
      help="owners"
      actions={
        <HelpAction feature="owners">
          <a className="button secondary" href="/api/v1/inventory/export">
            <Download size={16} />
            {t("exportInventory")}
          </a>
        </HelpAction>
      }
    >
      <p className="notice">{t("ownerSeparation")}</p>
      <Panel>
        <div className="toolbar">
          <div className="search">
            <Search size={17} />
            <input
              aria-label={t("searchOwner")}
              placeholder={t("searchOwner")}
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setPage(0);
              }}
            />
          </div>
          <input
            aria-label={t("militaryRank")}
            placeholder={t("militaryRank")}
            value={rank}
            onChange={(e) => {
              setRank(e.target.value);
              setPage(0);
            }}
          />
        </div>
        <DataError error={error} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {[
                  "device",
                  "assignedOwner",
                  "militaryRank",
                  "currentUser",
                  "status",
                  "actions",
                ].map((k) => (
                  <th key={k}>{t(k)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data?.items?.map((d: any) => (
                <tr key={d.id}>
                  <td>
                    <a href={"#devices/" + d.id}>{d.hostname}</a>
                  </td>
                  <td>
                    {d.owner_name || t("notAssigned")}
                    <small>
                      {d.owner_verified
                        ? t("identityVerified")
                        : t("unverified")}
                    </small>
                  </td>
                  <td>{d.owner_rank || "—"}</td>
                  <td>{d.last_user_account || "—"}</td>
                  <td>
                    <State value={d.identity_status} />
                  </td>
                  <td>
                    <div className="button-row">
                      <HelpAction feature="owners">
                        <button
                          className="button secondary"
                          onClick={() => edit(d)}
                        >
                          {t("assignOwner")}
                        </button>
                      </HelpAction>
                      <HelpAction feature="identityHistory">
                        <button
                          className="button secondary"
                          onClick={() =>
                            modal({
                              title: "identityHistory",
                              content: <IdentityRecords id={d.id} />,
                            })
                          }
                        >
                          {t("identityHistory")}
                        </button>
                      </HelpAction>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="pagination">
          <span>
            {data?.total ?? 0} {t("devices")}
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
      </Panel>
    </Page>
  );
}
function IdentityRecords({ id }: { id: string }) {
  const { t, revision, modal } = useTools(),
    users = useData<any[]>(`/devices/${id}/identities`, revision),
    history = useData<any[]>(`/devices/${id}/owner-history`, revision);
  return (
    <div className="modal-content">
      <h3>
        {t("userReported")} <HelpButton id="owners" />
      </h3>
      {users.data?.map((u) => (
        <div className="list-row" key={u.id}>
          <div>
            <b>{u.full_name}</b>
            <small>
              {u.military_rank || t("noRank")} · {u.windows_account}
            </small>
            <small>{fmt(u.submitted_at)}</small>
          </div>
          <HelpAction feature="correctIdentity">
            <button
              className="button secondary"
              onClick={() =>
                modal({
                  title: "correctIdentity",
                  fields: [
                    {
                      name: "full_name",
                      label: "fullName",
                      value: u.full_name,
                    },
                    {
                      name: "military_rank",
                      label: "militaryRank",
                      value: u.military_rank || "",
                      required: false,
                    },
                    {
                      name: "verified",
                      label: "identityVerified",
                      type: "checkbox",
                      value: u.verified,
                    },
                    reason,
                  ],
                  submit: (v) =>
                    api(`/devices/${id}/identities/${u.id}`, "PATCH", v),
                })
              }
            >
              {t("correctIdentity")}
            </button>
          </HelpAction>
        </div>
      ))}
      <h3>{t("assignmentHistory")}</h3>
      {history.data?.map((h) => (
        <div className="list-row" key={h.id}>
          <span>
            {h.full_name || t("notAssigned")} · {h.military_rank || "—"}
            <small>{h.reason}</small>
          </span>
          <span>{fmt(h.at)}</span>
        </div>
      ))}
    </div>
  );
}
function Incidents({ diagnostics }: { diagnostics: boolean }) {
  const { t, revision, modal } = useTools(),
    [state, setState] = useState(""),
    [group, setGroup] = useState(""),
    { data, error } = useData(
      `/incidents?state=${state}&group_id=${group}`,
      revision,
    ),
    groups = useData<any[]>("/mikrotik/groups", revision);
  return (
    <Page title={diagnostics ? "diagnostics" : "incidents"} help="incidents">
      <p className="notice">{t("inferenceNotice")}</p>
      <Panel>
        <div className="toolbar">
          <select
            aria-label={t("status")}
            value={state}
            onChange={(e) => setState(e.target.value)}
          >
            <option value="">{t("allStates")}</option>
            {["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"].map((v) => (
              <option key={v} value={v}>
                {t(v)}
              </option>
            ))}
          </select>
          <select
            aria-label={t("ap-groups")}
            value={group}
            onChange={(e) => setGroup(e.target.value)}
          >
            <option value="">{t("allGroups")}</option>
            {groups.data?.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </div>
        <DataError error={error} />
        {data?.items?.map((i: any) => (
          <article className="incident-card" key={i.id}>
            <div className="incident-title">
              <ShieldAlert size={22} />
              <h2>{t(i.title_key)}</h2>
              <State value={i.severity} />
              <State value={i.state} />
            </div>
            <p>
              <strong>{t("probableCause")}: </strong>
              {t(i.cause_key)} · {t("confidence")}: {t(i.confidence)}
            </p>
            <p>
              {i.router_ids.length} {t("access-points")} · {i.device_ids.length}{" "}
              {t("devices")} · {fmt(i.first_detected)} — {fmt(i.last_observed)}
            </p>
            <ul>
              {i.recommendations.map((r: string) => (
                <li key={r}>{t(r)}</li>
              ))}
            </ul>
            <details>
              <summary>{t("observedFacts")}</summary>
              <Json value={i.facts} />
            </details>
            <div className="button-row">
              {i.router_ids.map((id: string) => (
                <a
                  className="button secondary"
                  key={id}
                  href={"#access-points/" + id}
                >
                  {t("access-points")} {id.slice(0, 8)}
                </a>
              ))}
              <HelpAction feature="incidents">
                <button
                  className="button secondary"
                  onClick={() =>
                    modal({
                      title: "updateIncident",
                      fields: [
                        {
                          name: "state",
                          label: "status",
                          type: "select",
                          value: i.state,
                          options: [
                            "OPEN",
                            "ACKNOWLEDGED",
                            "INVESTIGATING",
                            "RESOLVED",
                          ].map((value) => ({ value, label: t(value) })),
                        },
                        {
                          name: "assigned_to",
                          label: "assigneeId",
                          required: false,
                        },
                        reason,
                      ],
                      submit: (v) =>
                        api("/incidents/" + i.id, "PATCH", {
                          ...v,
                          assigned_to: v.assigned_to || null,
                        }),
                    })
                  }
                >
                  {t("updateIncident")}
                </button>
              </HelpAction>
            </div>
          </article>
        ))}
        {!data?.items?.length && <p>{t("noIncidents")}</p>}
      </Panel>
    </Page>
  );
}
function Topology() {
  const { t, revision } = useTools(),
    [apGroup, setApGroup] = useState(""),
    [deviceGroup, setDeviceGroup] = useState(""),
    [health, setHealth] = useState(""),
    [subnet, setSubnet] = useState(""),
    [selected, setSelected] = useState<any>(null),
    { data, error } = useData(
      `/network/topology?group_id=${apGroup}&device_group_id=${deviceGroup}&health=${health}&subnet=${encodeURIComponent(subnet)}`,
      revision,
    ),
    aps = useData<any[]>("/mikrotik/groups", revision),
    groups = useData<any[]>("/groups", revision);
  const nodes: any[] = data?.nodes || [],
    positions = new Map<string, { x: number; y: number }>();
  const levels: Record<string, number> = {
    server: 80,
    router: 350,
    subnet: 600,
    device: 870,
    ap_group: 100,
    device_group: 1010,
    vlan: 650,
  };
  const counts: Record<string, number> = {};
  for (const n of nodes) {
    const count = counts[n.kind] || 0;
    counts[n.kind] = count + 1;
    positions.set(n.id, {
      x: levels[n.kind] || 600,
      y: (n.kind === "ap_group" ? 170 : 60) + count * 95,
    });
  }
  const height = Math.max(
    300,
    ...Object.values(counts).map((v) => v * 95 + 40),
  );
  return (
    <Page title="topology" help="topology">
      <Panel>
        <div className="toolbar topology-filters">
          <select
            value={apGroup}
            aria-label={t("ap-groups")}
            onChange={(e) => setApGroup(e.target.value)}
          >
            <option value="">{t("allApGroups")}</option>
            {aps.data?.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
          <select
            value={deviceGroup}
            aria-label={t("device-groups")}
            onChange={(e) => setDeviceGroup(e.target.value)}
          >
            <option value="">{t("allDeviceGroups")}</option>
            {groups.data?.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
          <select
            value={health}
            aria-label={t("health")}
            onChange={(e) => setHealth(e.target.value)}
          >
            <option value="">{t("allStates")}</option>
            <option>ONLINE</option>
            <option>UNAVAILABLE</option>
          </select>
          <input
            value={subnet}
            aria-label={t("cidr")}
            placeholder={t("cidr")}
            onChange={(e) => setSubnet(e.target.value)}
          />
        </div>
        <p className="notice">{t("topologyNotice")}</p>
        <DataError error={error} />
        <div className="topology-canvas">
          <svg
            viewBox={`0 0 1080 ${height}`}
            aria-label={t("topology")}
            role="img"
          >
            {data?.edges?.map((e: any, i: number) => {
              const a = positions.get(e.source),
                b = positions.get(e.target);
              return a && b ? (
                <path
                  key={i}
                  d={`M${a.x + 55},${a.y} C${a.x + 150},${a.y} ${b.x - 120},${b.y} ${b.x - 55},${b.y}`}
                  className={"topology-link " + e.assurance.toLowerCase()}
                >
                  <title>{t(e.assurance)}</title>
                </path>
              ) : null;
            })}
            {nodes.map((n) => {
              const p = positions.get(n.id)!;
              return (
                <g
                  key={n.id}
                  transform={`translate(${p.x},${p.y})`}
                  className={"topology-node " + n.kind}
                  role="button"
                  tabIndex={0}
                  aria-label={n.name}
                  onClick={() => setSelected(n)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") setSelected(n);
                  }}
                >
                  <rect x="-64" y="-26" width="128" height="55" rx="8" />
                  <text textAnchor="middle" y="-3">
                    {n.name.slice(0, 19)}
                  </text>
                  <text textAnchor="middle" className="node-state" y="15">
                    {t(n.state)}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        <div className="topology-legend">
          <span className="solid-line" />
          {t("OBSERVED")}
          <span className="dashed-line" />
          {t("UNKNOWN")}
        </div>
        {selected && (
          <div className="notice">
            <b>{selected.name}</b>
            <p>{t(selected.kind)}</p>
            {selected.kind === "device" || selected.kind === "router" ? (
              <a
                className="button secondary"
                href={
                  "#" +
                  (selected.kind === "device" ? "devices/" : "access-points/") +
                  selected.id
                }
              >
                {t("viewDetails")}
              </a>
            ) : (
              <Json value={selected} />
            )}
          </div>
        )}
      </Panel>
    </Page>
  );
}
function Jobs() {
  const { t, revision, modal } = useTools(),
    { data, error } = useData<any[]>("/network/operations", revision);
  return (
    <Page title="maintenance-jobs" help="schedule">
      <Panel>
        <DataError error={error} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {["actions", "status", "schedule", "reason", "progress"].map(
                  (k) => (
                    <th key={k}>{t(k)}</th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {data?.map((b) => (
                <tr key={b.id}>
                  <td>{t(b.operation)}</td>
                  <td>
                    <State value={b.state} />
                  </td>
                  <td>{fmt(b.not_before)}</td>
                  <td>{b.reason}</td>
                  <td>
                    <HelpAction feature="viewDetails">
                      <button
                        className="button secondary"
                        onClick={() =>
                          modal({
                            title: "progress",
                            content: <BatchReview id={b.id} />,
                          })
                        }
                      >
                        {t("viewDetails")}
                      </button>
                    </HelpAction>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </Page>
  );
}
function Recovery() {
  const { t, revision, modal } = useTools(),
    routers = useData<any[]>("/mikrotik/routers", revision),
    windows = useData<any[]>("/maintenance-windows", revision);
  return (
    <Page
      title="recovery-settings"
      help="recovery"
      actions={
        <HelpAction feature="schedule">
          <button
            className="button primary"
            onClick={() =>
              modal({
                title: "createWindow",
                fields: [
                  { name: "name", label: "name" },
                  {
                    name: "starts_at",
                    label: "windowStart",
                    type: "datetime-local",
                  },
                  {
                    name: "ends_at",
                    label: "windowEnd",
                    type: "datetime-local",
                  },
                  {
                    name: "router_ids",
                    label: "routerIds",
                    type: "textarea",
                    value: "[]",
                  },
                ],
                submit: (v) =>
                  api("/maintenance-windows", "POST", {
                    ...v,
                    starts_at: new Date(v.starts_at).toISOString(),
                    ends_at: new Date(v.ends_at).toISOString(),
                    router_ids: JSON.parse(v.router_ids),
                  }),
              })
            }
          >
            {t("createWindow")}
          </button>
        </HelpAction>
      }
    >
      <p className="notice">{t("recoveryNotice")}</p>
      <Panel>
        {routers.data?.map((r) => (
          <div className="list-row" key={r.id}>
            <span>
              <b>{r.name}</b>
              <small>
                {t(r.role)} ·{" "}
                {r.protected ? t("protected") : t("standardInfrastructure")}
              </small>
            </span>
            <HelpAction feature="recovery">
              <button
                className="button secondary"
                onClick={() =>
                  modal({
                    title: "configureRecovery",
                    info: t("recoveryNotice"),
                    fields: [
                      {
                        name: "enabled",
                        label: "enabled",
                        type: "checkbox",
                        value: r.recovery_policy?.enabled || false,
                      },
                      {
                        name: "recover_resources",
                        label: "recoverResources",
                        type: "checkbox",
                        value: (
                          r.recovery_policy?.conditions || ["resource_pressure"]
                        ).includes("resource_pressure"),
                      },
                      {
                        name: "recover_radio",
                        label: "recoverRadio",
                        type: "checkbox",
                        value: (r.recovery_policy?.conditions || []).includes(
                          "unexpected_radio_disabled",
                        ),
                      },
                      {
                        name: "sustained_seconds",
                        label: "sustainedSeconds",
                        type: "number",
                        value: r.recovery_policy?.sustained_seconds || 300,
                      },
                      {
                        name: "cooldown_seconds",
                        label: "cooldownSeconds",
                        type: "number",
                        value: r.recovery_policy?.cooldown_seconds || 3600,
                      },
                      {
                        name: "max_attempts_per_day",
                        label: "maxAttempts",
                        type: "number",
                        value: r.recovery_policy?.max_attempts_per_day || 2,
                      },
                      {
                        name: "independent_management_router_ids",
                        label: "independentPaths",
                        type: "textarea",
                        value: JSON.stringify(
                          r.recovery_policy
                            ?.independent_management_router_ids || [],
                        ),
                      },
                      {
                        name: "require_maintenance_window",
                        label: "requireWindow",
                        type: "checkbox",
                        value:
                          r.recovery_policy?.require_maintenance_window !==
                          false,
                      },
                    ],
                    submit: (v) =>
                      api(`/mikrotik/routers/${r.id}/recovery-policy`, "PUT", {
                        ...v,
                        conditions: [
                          ...(v.recover_resources ? ["resource_pressure"] : []),
                          ...(v.recover_radio
                            ? ["unexpected_radio_disabled"]
                            : []),
                        ],
                        independent_management_router_ids: JSON.parse(
                          v.independent_management_router_ids,
                        ),
                      }),
                  })
                }
              >
                {t("configureRecovery")}
              </button>
            </HelpAction>
          </div>
        ))}
      </Panel>
      <Panel title="maintenanceWindows">
        {windows.data?.map((w) => (
          <div className="list-row" key={w.id}>
            <b>{w.name}</b>
            <span>
              {fmt(w.starts_at)} — {fmt(w.ends_at)}
            </span>
          </div>
        ))}
      </Panel>
    </Page>
  );
}
function Administrators() {
  const { t, revision, modal } = useTools(),
    { data, error } = useData<any[]>("/administrators", revision);
  return (
    <Page
      title="administrators"
      help="mfa"
      actions={
        <HelpAction feature="secrets">
          <button
            className="button primary"
            onClick={() =>
              modal({
                title: "createAdministrator",
                fields: [
                  { name: "username", label: "username" },
                  { name: "password", label: "password", type: "password" },
                  {
                    name: "role",
                    label: "role",
                    type: "select",
                    options: ["owner", "operator", "viewer", "deployer"].map(
                      (value) => ({ value, label: t(value) }),
                    ),
                  },
                ],
                submit: (v) => api("/administrators", "POST", v),
              })
            }
          >
            {t("createAdministrator")}
          </button>
        </HelpAction>
      }
    >
      <Panel>
        <DataError error={error} />
        {data?.map((a) => (
          <div className="list-row" key={a.id}>
            <span>
              <b>{a.username}</b>
              <small>
                {t(a.role)} ·{" "}
                {a.mfa_enabled ? t("optionalOtp") : t("passwordLogin")}
              </small>
            </span>
            <HelpAction feature="editDevice">
              <button
                className="button secondary"
                onClick={() =>
                  modal({
                    title: "editDevice",
                    fields: [
                      {
                        name: "enabled",
                        label: "enabled",
                        type: "checkbox",
                        value: a.enabled,
                      },
                      {
                        name: "role",
                        label: "role",
                        type: "select",
                        value: a.role,
                        options: [
                          "owner",
                          "operator",
                          "viewer",
                          "deployer",
                        ].map((value) => ({ value, label: t(value) })),
                      },
                    ],
                    submit: (v) => api("/administrators/" + a.id, "PATCH", v),
                  })
                }
              >
                {t("editDevice")}
              </button>
            </HelpAction>
          </div>
        ))}
      </Panel>
    </Page>
  );
}
function SystemHealth() {
  const { t, revision } = useTools(),
    { data, error } = useData("/system/resources", revision);
  return (
    <Page title="system-health" help="metrics">
      <Panel>
        <DataError error={error} />
        <div className="detail-grid">
          {data &&
            Object.entries(data).map(([k, v]) => (
              <div key={k}>
                <span>{t(k)}</span>
                <strong>
                  {typeof v === "boolean"
                    ? t(v ? "enabled" : "disabled")
                    : String(v ?? t("unavailable"))}
                </strong>
              </div>
            ))}
        </div>
      </Panel>
    </Page>
  );
}
function MonitoringSettings() {
  const { t, revision, modal } = useTools(),
    { data, error } = useData("/system/monitoring-settings", revision);
  return (
    <Page title="monitoring-settings" help="metrics">
      <Panel>
        <DataError error={error} />
        <Json value={data} />
        <HelpAction feature="metrics">
          <button
            className="button primary"
            onClick={() =>
              modal({
                title: "monitoring-settings",
                fields: [
                  {
                    name: "low_resource_mode",
                    label: "lowResource",
                    type: "checkbox",
                    value: data?.low_resource_mode ?? true,
                  },
                  {
                    name: "network_health_seconds",
                    label: "healthInterval",
                    type: "number",
                    value: data?.network_health_seconds ?? 60,
                  },
                  {
                    name: "network_inventory_seconds",
                    label: "inventoryInterval",
                    type: "number",
                    value: data?.network_inventory_seconds ?? 900,
                  },
                  {
                    name: "network_poll_concurrency",
                    label: "pollConcurrency",
                    type: "number",
                    value: data?.network_poll_concurrency ?? 2,
                  },
                  {
                    name: "telemetry_retention_days",
                    label: "retentionDays",
                    type: "number",
                    value: data?.telemetry_retention_days ?? 7,
                  },
                  {
                    name: "recovery_enabled",
                    label: "autoRecoveryEnabled",
                    type: "checkbox",
                    value: data?.recovery_enabled ?? false,
                  },
                  reason,
                ],
                submit: (v) => api("/system/monitoring-settings", "PUT", v),
              })
            }
          >
            {t("editDevice")}
          </button>
        </HelpAction>
      </Panel>
    </Page>
  );
}

function PolicyLayers() {
  const { t, revision, modal } = useTools(),
    [selected, setSelected] = useState(""),
    policies = useData<any[]>("/policies", revision),
    layers = useData<any[]>(
      selected ? `/policies/${selected}/layers` : "/groups",
      revision,
    ),
    groups = useData<any[]>("/groups", revision);
  return (
    <Page title="policyLayers" help="policies">
      <p className="notice">{t("policyConflictNotice")}</p>
      <Panel>
        <label>
          {t("policy")}
          <select
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
          >
            <option value="">—</option>
            {policies.data?.map((p) => (
              <option value={p.id} key={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        {selected && (
          <>
            <HelpAction feature="policies">
              <button
                className="button primary"
                onClick={() =>
                  modal({
                    title: "addPolicyLayer",
                    info: t("policyConflictNotice"),
                    fields: [
                      {
                        name: "scope",
                        label: "scope",
                        type: "select",
                        options: ["GLOBAL", "CLASS", "GROUP", "DEVICE"].map(
                          (value) => ({ value, label: t(value) }),
                        ),
                      },
                      { name: "target", label: "scopeTarget", required: false },
                      {
                        name: "controls",
                        label: "layerControls",
                        type: "textarea",
                        value: '{"require_d":true}',
                      },
                      {
                        name: "approved_relaxation",
                        label: "approveRelaxation",
                        type: "checkbox",
                      },
                      reason,
                    ],
                    submit: (v) =>
                      api(`/policies/${selected}/layers`, "POST", {
                        ...v,
                        target: v.target || null,
                        controls: JSON.parse(v.controls),
                      }),
                  })
                }
              >
                {t("addPolicyLayer")}
              </button>
            </HelpAction>
            <DataError error={layers.error} />
            {layers.data?.map((l) => (
              <div className="list-row" key={l.id}>
                <div>
                  <b>
                    {t(l.scope)} ·{" "}
                    {groups.data?.find((g) => g.id === l.target)?.name ||
                      l.target ||
                      t("global")}
                  </b>
                  <p>{l.reason}</p>
                  <Json value={l.controls} />
                </div>
                <HelpAction feature="policies">
                  <button
                    className="button secondary danger"
                    onClick={() =>
                      modal({
                        title: "revoke",
                        info: t("templateStaged"),
                        fields: [reason],
                        submit: () =>
                          api(`/policies/${selected}/layers/${l.id}`, "DELETE"),
                      })
                    }
                  >
                    {t("revoke")}
                  </button>
                </HelpAction>
              </div>
            ))}
          </>
        )}
      </Panel>
    </Page>
  );
}

function ConnectedClients() {
  const { t, revision } = useTools(),
    [page, setPage] = useState(0),
    [group, setGroup] = useState(""),
    [query, setQuery] = useState(""),
    groups = useData<any[]>("/mikrotik/groups", revision),
    { data, error } = useData(
      `/network/clients?limit=50&offset=${page * 50}&group_id=${encodeURIComponent(group)}&q=${encodeURIComponent(query)}`,
      revision,
    );
  return (
    <Page title="connected-clients" help="ap-inventory">
      <p className="notice">{t("associationNotice")}</p>
      <Panel>
        <div className="toolbar">
          <label className="search">
            <Search size={15} />
            <input
              aria-label={t("searchClients")}
              placeholder={t("searchClients")}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(0);
              }}
            />
          </label>
          <select
            aria-label={t("ap-groups")}
            value={group}
            onChange={(e) => {
              setGroup(e.target.value);
              setPage(0);
            }}
          >
            <option value="">{t("allGroups")}</option>
            {groups.data?.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </div>
        <DataError error={error} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {[
                  "device",
                  "endpointLabel",
                  "mac",
                  "ap",
                  "ssid",
                  "signal",
                  "lastSeen",
                  "status",
                ].map((k) => (
                  <th key={k}>{t(k)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data?.items?.map((c: any, n: number) => (
                <tr key={n}>
                  <td>
                    {c.device_id ? (
                      <a href={"#devices/" + c.device_id}>{c.hostname}</a>
                    ) : (
                      c.hostname || "—"
                    )}
                    <small>
                      {t(c.registered ? "registeredInSuro" : "notRegistered")}
                    </small>
                  </td>
                  <td>{c.label || "—"}</td>
                  <td className="mono">{c.observation["mac-address"]}</td>
                  <td>
                    <a href={"#access-points/" + c.access_point_id}>
                      {c.access_point}
                    </a>
                  </td>
                  <td>{c.observation.ssid || "—"}</td>
                  <td>
                    {c.observation.signal ||
                      c.observation["signal-strength"] ||
                      c.observation["rx-signal"] ||
                      "—"}
                  </td>
                  <td>{fmt(c.observed_at)}</td>
                  <td>{t(c.fresh ? "observed" : "stale")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="pagination">
          <span>{data?.total ?? 0}</span>
          <button disabled={!page} onClick={() => setPage((p) => p - 1)}>
            {t("previous")}
          </button>
          <button
            disabled={(page + 1) * 50 >= (data?.total || 0)}
            onClick={() => setPage((p) => p + 1)}
          >
            {t("next")}
          </button>
        </div>
      </Panel>
    </Page>
  );
}

const CATEGORIES = [
  "UNKNOWN",
  "INFRASTRUCTURE",
  "ADMIN_WORKSTATION",
  "COMPUTER_UNMANAGED",
  "PRINTER",
  "PHONE_TABLET",
  "IOT",
  "OTHER",
];
const ENROLLMENT = [
  "NOT_REGISTERED",
  "REGISTERED_NOT_ENROLLED",
  "ENROLLED_NO_HEARTBEAT",
  "AGENT_STALE",
  "AGENT_HEALTHY",
  "EXEMPT_UNMANAGED",
];

function NetworkInventory() {
  const { t, revision, modal, refresh, identity } = useTools(),
    [page, setPage] = useState(0),
    [query, setQuery] = useState(""),
    [state, setState] = useState(""),
    { data, error } = useData<any>(
      `/network/inventory?limit=50&offset=${page * 50}&q=${encodeURIComponent(query)}&enrollment=${state}`,
      revision,
    ),
    canEdit = identity.role === "owner" || identity.role === "operator";
  const classify = (row: any) =>
    modal({
      title: "classify",
      info: <p className="notice">{t("inventoryNotice")}</p>,
      fields: [
        {
          name: "category",
          label: "category",
          value: row.category,
          options: CATEGORIES.map((c) => ({ value: c, label: t("cat_" + c) })),
        },
        { name: "label", label: "endpointLabel", value: row.label },
        {
          name: "note",
          label: "endpointNote",
          value: row.note,
          type: "textarea",
        },
      ],
      submit: async (v) => {
        await api(
          `/network/inventory/${encodeURIComponent(row.mac)}/label`,
          "PUT",
          v,
        );
        refresh();
      },
    });
  return (
    <Page title="network-inventory" help="network-inventory">
      <p className="notice">{t("inventoryNotice")}</p>
      <div className="count-badges">
        {ENROLLMENT.filter((s) => data?.summary?.[s]).map((s) => (
          <span className="count-tag" key={s}>
            {t(s)}: {data.summary[s]}
          </span>
        ))}
      </div>
      {data?.access_points?.length > 0 && (
        <Panel title="capsmanAccessPoints">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {[
                    "name",
                    "mac",
                    "board",
                    "version",
                    "status",
                    "controller",
                  ].map((k) => (
                    <th key={k}>{t(k)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.access_points.map((ap: any, n: number) => (
                  <tr key={n}>
                    <td>{ap.identity || "—"}</td>
                    <td className="mono">{ap.mac || ap.address || "—"}</td>
                    <td>{ap.board || "—"}</td>
                    <td>{ap.version || "—"}</td>
                    <td>{ap.state || "—"}</td>
                    <td>{ap.controller}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
      <Panel>
        <div className="toolbar">
          <label className="search">
            <Search size={15} />
            <input
              aria-label={t("searchInventory")}
              placeholder={t("searchInventory")}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(0);
              }}
            />
          </label>
          <select
            aria-label={t("suroClient")}
            value={state}
            onChange={(e) => {
              setState(e.target.value);
              setPage(0);
            }}
          >
            <option value="">{t("allStates")}</option>
            {ENROLLMENT.map((s) => (
              <option key={s} value={s}>
                {t(s)}
              </option>
            ))}
          </select>
        </div>
        <DataError error={error} />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {[
                  "ipAddress",
                  "mac",
                  "hostname",
                  "sources",
                  "suroClient",
                  "category",
                  "router",
                ].map((k) => (
                  <th key={k}>{t(k)}</th>
                ))}
                <th>
                  <HelpButton id="network-inventory" />
                </th>
              </tr>
            </thead>
            <tbody>
              {data?.items?.map((row: any) => (
                <tr key={row.mac}>
                  <td>
                    {row.addresses.join(", ") || "—"}
                    {row.duplicate_address.length > 0 && (
                      <small className="badge error">{t("duplicateIp")}</small>
                    )}
                  </td>
                  <td className="mono">
                    {row.mac}
                    {row.randomized_mac && (
                      <small className="badge unknown">{t("randomMac")}</small>
                    )}
                  </td>
                  <td>
                    {row.device_id ? (
                      <a href={"#devices/" + row.device_id}>
                        {row.device_hostname}
                      </a>
                    ) : (
                      row.hostnames.join(", ") || "—"
                    )}
                    {row.label && <small>{row.label}</small>}
                  </td>
                  <td>
                    {row.sources.map((s: string) => t(s)).join(" · ")}
                    {!row.fresh && <small>{t("stale")}</small>}
                  </td>
                  <td>
                    <State value={row.enrollment} />
                  </td>
                  <td>{t("cat_" + row.category)}</td>
                  <td>
                    {row.wifi?.access_point ||
                      row.mikrotik_router ||
                      row.routers.join(", ")}
                  </td>
                  <td>
                    {canEdit && (
                      <button
                        className="button secondary"
                        onClick={() => classify(row)}
                      >
                        <Edit size={14} />
                        {t("classify")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="pagination">
          <span>{data?.total ?? 0}</span>
          <button disabled={!page} onClick={() => setPage((p) => p - 1)}>
            {t("previous")}
          </button>
          <button
            disabled={(page + 1) * 50 >= (data?.total || 0)}
            onClick={() => setPage((p) => p + 1)}
          >
            {t("next")}
          </button>
        </div>
      </Panel>
    </Page>
  );
}
