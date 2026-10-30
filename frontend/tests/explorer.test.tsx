// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { NetworkExplorer } from "../src/pages/NetworkExplorer";
import { AdminCredentialPanel } from "../src/components/AdminCredential";
import { WorkContext } from "../src/context";
import { LocaleContext, type Language } from "../src/i18n";
import en from "../src/locales/en.json";
import hy from "../src/locales/hy.json";
import ru from "../src/locales/ru.json";

const computer = (over: any) => ({
  mac: "A8:3B:76:00:00:01",
  owner: null,
  rank: null,
  groups: [],
  wifi: "UNKNOWN",
  ap_id: null,
  last_ap_id: null,
  signal: null,
  wifi_observed_at: null,
  agent: "NEVER",
  last_heartbeat: null,
  compliance: "UNVERIFIED",
  score: 0,
  awaiting_enforcement: false,
  failed_operations: 0,
  never_seen: false,
  ...over,
});
const explorer = {
  ap_groups: [{ id: "g1", name: "Building A" }],
  device_groups: [{ id: "dg1", name: "Room 5" }],
  access_points: [
    {
      id: "ap1", name: "AP-01", kind: "access_point", status: "ONLINE", last_seen: null, controller_id: null,
      groups: ["g1"], fresh: true, clients_total: 3, registered_now: ["d1"], unregistered_now: 2,
      previously_seen: ["d3"],
    },
  ],
  devices: [
    computer({ id: "d1", hostname: "PC-ONLINE", wifi: "ASSOCIATED", ap_id: "ap1", agent: "ONLINE", compliance: "COMPLIANT", score: 100, groups: ["dg1"] }),
    computer({ id: "d2", hostname: "PC-WIRED", agent: "ONLINE", compliance: "NONCOMPLIANT", awaiting_enforcement: true }),
    computer({ id: "d3", hostname: "PC-GONE", wifi: "NOT_ASSOCIATED", last_ap_id: "ap1", agent: "STALE" }),
    computer({ id: "d4", hostname: "PC-NEW", never_seen: true }),
  ],
  counts: {
    registered: 4, wifi_associated: 1, agent_online: 2, agent_offline: 2, compliant: 1, noncompliant: 1,
    awaiting_enforcement: 1, failed_operations: 0, offline: 1, never_seen: 1, ungrouped: 3, unregistered_clients: 2,
  },
};
const credential = {
  credential: { account: "AcademyAdmin", scheme: "LEGACY_MAC_V1", source_mac: "A4:C3:F0:85:7E:21", status: "UNVERIFIED", verified_at: null, revision: 1 },
  legacy: {
    reported: true, startup_task: { state: "Ready" }, kursant_username: "student", allowed_addresses: ["10.47.47.47"], server_address: "10.0.0.5",
    winre: "DISABLED", findings: ["legacy.firewall_reset_at_boot", "legacy.server_blocked_after_boot"],
  },
  candidates: [{ mac: "A4:C3:F0:85:7E:21", adapter: "Wi-Fi", status: "Up", source: "current", classified: true }],
};
vi.mock("../src/api/client", () => ({ api: vi.fn(async () => ({})) }));
vi.mock("../src/hooks/useData", () => ({
  useData: (path: string) => ({ data: path === "/network/explorer" ? explorer : credential, error: "" }),
}));
afterEach(cleanup);

function renderWith(node: any, language: Language = "en", role = "owner") {
  const modal = vi.fn();
  render(
    <LocaleContext.Provider value={{ language, setLanguage: () => {} }}>
      <WorkContext.Provider
        value={{ revision: 0, refresh: () => {}, modal, run: async () => {}, identity: { username: "a", role, csrf: "", mfa: true } }}
      >
        {node}
      </WorkContext.Provider>
    </LocaleContext.Provider>,
  );
  return modal;
}

it("expands groups to access points and selects a connected computer", () => {
  renderWith(<NetworkExplorer />);
  const tree = screen.getAllByRole("tree")[0];
  fireEvent.click(within(tree).getByText("Building A"));
  fireEvent.click(within(tree).getByText("AP-01"));
  // Selecting the AP shows its details and its computers.
  expect(screen.getByRole("link", { name: en.openAccessPoint })).toHaveProperty("hash", "#access-points/ap1");
  fireEvent.click(within(tree).getByText("PC-ONLINE"));
  expect(screen.getByRole("link", { name: en.openComputer })).toHaveProperty("hash", "#devices/d1");
  fireEvent.click(within(tree).getByText(en.previouslySeen));
  expect(within(tree).getByText("PC-GONE")).toBeTruthy();
});

it("keeps registered, Wi-Fi and agent status apart and filters by each", () => {
  renderWith(<NetworkExplorer />);
  const tree = screen.getAllByRole("tree")[0];
  fireEvent.click(within(tree).getByText(en["bucket.agent_only"]));
  // Agent online over a cable: Wi-Fi is unknown, not offline.
  const wired = within(tree).getByText("PC-WIRED").closest("button")!;
  expect(wired.textContent).toContain(en["agentState.ONLINE"]);
  expect(wired.textContent).toContain(en["wifiState.UNKNOWN"]);
  fireEvent.click(within(tree).getByText(en["bucket.never_seen"], { selector: ".tree-label" }));
  expect(within(tree).getByText("PC-NEW").closest("button")!.textContent).toContain(en["count.never_seen"]);
  const chip = screen.getByRole("button", { name: /1\s*Awaiting enforcement/ });
  fireEvent.click(chip);
  expect(chip.getAttribute("aria-pressed")).toBe("true");
  expect(within(tree).queryByText("PC-NEW")).toBeNull();
  fireEvent.change(screen.getByLabelText(en.searchExplorer), { target: { value: "wired" } });
  expect(screen.getByRole("tree", { name: en.searchResults })).toBeTruthy();
});

it("renders every explorer and credential string in Armenian and Russian", () => {
  for (const [language, catalog] of [["hy", hy], ["ru", ru]] as const) {
    renderWith(<NetworkExplorer />, language);
    expect(screen.getByText(catalog.suroNetwork)).toBeTruthy();
    expect(screen.getByText(catalog["count.never_seen"])).toBeTruthy();
    cleanup();
    renderWith(<AdminCredentialPanel deviceId="d1" />, language);
    expect(screen.getByText(catalog["legacy.server_blocked_after_boot"])).toBeTruthy();
    expect(screen.getByText(catalog.revealPassword)).toBeTruthy();
    cleanup();
  }
  for (const key of Object.keys(en).filter((k) => /^(count|bucket|wifiState|agentState|sourceNote|legacy|credential)\./.test(k))) {
    expect(hy).toHaveProperty([key]);
    expect(ru).toHaveProperty([key]);
  }
});

it("asks for a reason before revealing and hides actions from non-owners", () => {
  const modal = renderWith(<AdminCredentialPanel deviceId="d1" />);
  expect(screen.getByText("student")).toBeTruthy();
  fireEvent.click(screen.getByText(en.revealPassword));
  expect(modal).toHaveBeenCalledWith(expect.objectContaining({ title: "revealPassword", fields: [{ name: "reason", label: "reason" }] }));
  cleanup();
  renderWith(<AdminCredentialPanel deviceId="d1" />, "en", "viewer");
  expect(screen.queryByText(en.revealPassword)).toBeNull();
  expect(screen.getByText(en.credentialOwnerOnly)).toBeTruthy();
});

it("offers to disable the old startup task through approved maintenance", () => {
  const modal = renderWith(<AdminCredentialPanel deviceId="d1" />);
  expect(screen.getByText(en.legacyTaskActive)).toBeTruthy();
  expect(screen.queryByText(en.replaceLegacyRules)).toBeNull();
  fireEvent.click(screen.getByText(en["legacy.retire_startup_task"]));
  expect(modal).toHaveBeenCalledWith(expect.objectContaining({ title: "legacy.retire_startup_task" }));
});
