// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { AdmissionPage, AdmissionDevicePanel } from "../src/pages/AdmissionPage";
import { WorkContext } from "../src/context";
import { LocaleContext, type Language } from "../src/i18n";
import en from "../src/locales/en.json";
import hy from "../src/locales/hy.json";
import ru from "../src/locales/ru.json";

const policy = {
  mode: "PILOT", require_enrollment: true, require_running_agent: true, require_compliance: false, exempt_developers: true,
  heartbeat_timeout_seconds: 300, grace_seconds: 300, auto_revoke: true, onboarding_enabled: true, outage_policy: "EXPIRE", revision: 1,
};
const row = {
  device_id: "d1", hostname: "Laptop-07", mac: "AA:BB:CC:DD:EE:FF", device_class: "STANDARD", exempt: false, exemption_reason: null,
  client: "ENROLLED", agent: "CONNECTED", agent_version: "0.3.0", last_heartbeat: "2026-10-30T10:00:00", registered_at: "2026-10-29T10:00:00",
  enrollment_id: "ab12cd34ef56", user: { first_name: "Արամ", last_name: "Պետրոսյան", full_name: "Արամ Պետրոսյան", military_rank: "Լեյտենանտ", verified: false },
  required: true, desired: "AUTHORIZED", reason: "admission.agent_verified", network: "AUTHORIZATION_PENDING", gate_state: "INSTALLED",
  applied: "NONE", granted_ip: null, grant_expires_at: null, reported_ip: "192.168.88.50", error: "safety.dry_run", override: null,
  override_until: null, onboarding_until: null, connected_ap: "MikroTik-02",
  rollback_commands: ['/ip firewall filter remove [find comment~"^lantern:d1:admission:"]'], logs: [],
};
vi.mock("../src/api/client", () => ({ api: vi.fn(async () => ({})) }));
vi.mock("../src/hooks/useData", () => ({
  useData: (path: string) => ({
    data: path.startsWith("/admission/overview")
      ? { policy, counts: { ENROLLED: 1, ENROLLMENT_PENDING: 0, NOT_ENROLLED: 0 }, items: [row] }
      : path.startsWith("/admission/devices/") ? row : path === "/mikrotik/routers" ? [{ id: "r1", name: "Gateway" }, { id: "c1", name: "CAP", controller_id: "r1" }] : null,
    error: "",
  }),
}));
afterEach(cleanup);

function renderWith(node: any, language: Language = "en") {
  const modal = vi.fn();
  render(
    <LocaleContext.Provider value={{ language, setLanguage: () => {} }}>
      <WorkContext.Provider value={{ revision: 0, refresh: () => {}, modal, run: async () => {}, identity: { username: "a", role: "owner", csrf: "", mfa: true } }}>
        {node}
      </WorkContext.Provider>
    </LocaleContext.Provider>,
  );
  return modal;
}

it("offers only disabled and pilot modes and a pilot MAC form limited to real routers", () => {
  const modal = renderWith(<AdmissionPage />);
  const mode = screen.getByLabelText(en["adm.mode"]) as HTMLSelectElement;
  const options = Object.fromEntries([...mode.options].map((o) => [o.value, o.disabled]));
  expect(options).toEqual({ DISABLED: false, PILOT: false, GROUPS: true, ALL: true });
  fireEvent.click(screen.getByRole("button", { name: en["adm.addPilot"] }));
  const spec = modal.mock.calls[0][0];
  expect(spec.fields.map((f: any) => f.name)).toEqual(["mac", "hostname", "router_id", "reason"]);
  expect(spec.fields[2].options).toEqual([{ value: "r1", label: "Gateway" }]);  // CAPs are observed only, never gated
});

it("shows the decision apart from what the router has confirmed", () => {
  renderWith(<AdmissionDevicePanel deviceId="d1" />);
  expect(screen.getByText(en["adm.network.AUTHORIZATION_PENDING"])).toBeTruthy();
  expect(screen.getByText(en["adm.desired.AUTHORIZED"])).toBeTruthy();
  expect(screen.getByRole("alert").textContent).toContain(en["adm.lastError"]);
  expect(screen.getByText("Լեյտենանտ")).toBeTruthy();
  expect(screen.getByText("MikroTik-02")).toBeTruthy();
  expect(screen.getByRole("button", { name: en["adm.removeGate"] })).toBeTruthy();
  expect(screen.queryByRole("button", { name: en["adm.prepareGate"] })).toBeNull();
});

it("asks for a reason before revoking network access", () => {
  const modal = renderWith(<AdmissionDevicePanel deviceId="d1" />);
  fireEvent.click(screen.getByRole("button", { name: en["adm.revokeNow"] }));
  expect(modal.mock.calls[0][0].fields.at(-1)).toEqual({ name: "reason", label: "reason" });
});

it("renders in Armenian and Russian and translates every status the server can return", () => {
  for (const [language, dict] of [["hy", hy], ["ru", ru]] as const) {
    renderWith(<AdmissionPage />, language);
    expect(screen.getAllByText(dict["adm.title"]).length).toBeGreaterThan(0);
    const table = screen.getByRole("table");
    expect(within(table).getByText(dict["adm.client.ENROLLED"])).toBeTruthy();
    cleanup();
  }
  const states = {
    client: ["ENROLLED", "ENROLLMENT_PENDING", "NOT_ENROLLED", "NOT_APPLICABLE"],
    agent: ["CONNECTED", "DISCONNECTED", "NEVER", "UNHEALTHY"],
    network: ["AUTHORIZED", "AUTHORIZATION_PENDING", "REVOCATION_PENDING", "RESTRICTED", "GATE_NOT_INSTALLED", "ERROR", "EXEMPT", "NOT_REQUIRED"],
    gate: ["NOT_INSTALLED", "PREVIEW", "INSTALLED", "REMOVING", "ERROR", "DRY_RUN"],
    class: ["STANDARD", "ADMINISTRATOR", "DEVELOPER", "INFRASTRUCTURE", "OTHER"],
  };
  const keys = Object.entries(states).flatMap(([prefix, values]) => values.map((v) => `adm.${prefix}.${v}`));
  for (const dict of [en, hy, ru] as Record<string, string>[]) for (const key of keys) expect(dict[key], key).toBeTruthy();
});
