import { useContext } from "react";
import { Eye, KeyRound, ShieldAlert } from "lucide-react";
import { api } from "../api/client";
import { WorkContext } from "../context";
import { useData } from "../hooks/useData";
import { useT } from "../i18n";
import { HelpAction } from "./Help";

type Candidate = {
  mac: string;
  adapter: string;
  status: string;
  source: string;
  classified: boolean;
};
type CredentialView = {
  credential: null | {
    account: string;
    scheme: string;
    source_mac: string | null;
    status: string;
    verified_at: string | null;
    revision: number;
  };
  legacy: {
    reported: boolean;
    kursant_username: string | null;
    allowed_addresses: string[];
    server_address: string | null;
    winre: string;
    findings: string[];
  };
  candidates: Candidate[];
};

/** Recoverable local administrator password: legacy MAC-derived or random. Never cached in page state. */
export function AdminCredentialPanel({ deviceId }: { deviceId: string }) {
  const t = useT();
  const { revision, modal, identity } = useContext(WorkContext);
  const base = "/devices/" + deviceId + "/admin-credential";
  const { data, error } = useData<CredentialView>(base, revision);
  const owner = identity.role === "owner";
  if (!data) return error ? <div className="error">{t(error)}</div> : null;
  const record = data.credential;
  const register = (scheme: string, mac?: string) =>
    modal({
      title: scheme === "RANDOM_V1" ? "generateAdminPassword" : "useLegacyMac",
      info: t(scheme === "RANDOM_V1" ? "randomPasswordNotice" : "legacyMacNotice"),
      fields: [
        ...(scheme === "RANDOM_V1"
          ? [{ name: "account", label: "adminAccount", value: "SuroAdmin" }]
          : []),
        { name: "reason", label: "reason" },
      ],
      submit: (v) =>
        api(base, "POST", {
          scheme,
          source_mac: mac,
          account: v.account,
          reason: v.reason,
          replace: !!record,
          revision: record?.revision,
        }),
    });
  const reveal = () =>
    modal({
      title: "revealPassword",
      info: t("revealNotice"),
      fields: [{ name: "reason", label: "reason" }],
      submit: async (v) => {
        const result = await api(base + "/reveal", "POST", v);
        // Shown once in a dialog; the value is not kept in component state or the URL.
        setTimeout(
          () =>
            modal({
              title: "revealPassword",
              content: (
                <div className="modal-content">
                  <p>
                    {t("adminAccount")}: <b>{result.account}</b>
                  </p>
                  <pre className="secret mono" aria-label={t("password")}>
                    {result.password}
                  </pre>
                  <p className="notice">{t("closeAfterUse")}</p>
                </div>
              ),
            }),
          0,
        );
      },
    });
  const record_result = () =>
    modal({
      title: "recordCredentialResult",
      info: t("recordCredentialNotice"),
      fields: [
        {
          name: "result",
          label: "result",
          type: "select",
          options: ["VERIFIED", "FAILED", "RETIRED"].map((v) => ({
            value: v,
            label: t("credential." + v),
          })),
        },
        { name: "reason", label: "reason" },
      ],
      submit: (v) =>
        api(base + "/verification", "POST", { ...v, revision: record!.revision }),
    });
  return (
    <>
      {data.legacy.findings.length > 0 && (
        <div className="notice warning" role="status">
          <ShieldAlert size={16} />
          <ul className="plain-list">
            {data.legacy.findings.map((f) => (
              <li key={f}>{t(f)}</li>
            ))}
          </ul>
          {data.legacy.allowed_addresses.length > 0 && (
            <p>
              {t("legacyAllowedAddresses")}:{" "}
              <code>{data.legacy.allowed_addresses.join(", ")}</code>
              {data.legacy.server_address && (
                <>
                  {" · "}
                  {t("suroServer")}: <code>{data.legacy.server_address}</code>
                </>
              )}
            </p>
          )}
          {data.legacy.kursant_username && (
            <p>
              {t("legacyStandardUser")}: <b>{data.legacy.kursant_username}</b>
            </p>
          )}
        </div>
      )}
      {!data.legacy.reported && <p className="notice">{t("legacyNotReported")}</p>}
      <div className="detail-grid">
        {[
          ["adminAccount", record?.account],
          ["scheme", record && t("credential." + record.scheme)],
          ["mac", record?.source_mac],
          ["status", record && t("credential." + record.status)],
        ].map(([k, v]) => (
          <div key={k}>
            <span>{t(k!)}</span>
            <strong>{v || "—"}</strong>
          </div>
        ))}
      </div>
      {owner ? (
        <div className="button-row">
          {record && record.status !== "RETIRED" && (
            <HelpAction feature="revealPassword">
              <button className="button primary" onClick={reveal}>
                <Eye size={16} />
                {t("revealPassword")}
              </button>
            </HelpAction>
          )}
          {record && (
            <button className="button secondary" onClick={record_result}>
              {t("recordCredentialResult")}
            </button>
          )}
          <HelpAction feature="generateAdminPassword">
            <button
              className="button secondary"
              onClick={() => register("RANDOM_V1")}
            >
              <KeyRound size={16} />
              {t("generateAdminPassword")}
            </button>
          </HelpAction>
        </div>
      ) : (
        <p className="notice">{t("credentialOwnerOnly")}</p>
      )}
      <h3>{t("legacyMacCandidates")}</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {["mac", "adapter", "status", "macSourceLabel", ""].map((k) => (
                <th key={k}>{k && t(k)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.candidates.map((c) => (
              <tr key={c.mac}>
                <td className="mono">{c.mac}</td>
                <td>{c.adapter || "—"}</td>
                <td>{c.status || "—"}</td>
                <td>{t("macSource." + c.source)}</td>
                <td>
                  {owner && c.mac !== record?.source_mac && (
                    <button
                      className="button secondary"
                      onClick={() => register("LEGACY_MAC_V1", c.mac)}
                    >
                      {t("useLegacyMac")}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
