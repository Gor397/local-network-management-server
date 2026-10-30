// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { PolicyStudio } from "../src/pages/PolicyStudio";
import { WorkContext } from "../src/context";
import { LocaleContext, type Language } from "../src/i18n";
import { api } from "../src/api/client";
import catalog from "./fixtures/policy-catalog.json";
import en from "../src/locales/en.json";
import hy from "../src/locales/hy.json";
import ru from "../src/locales/ru.json";

const published = { ...catalog.templates.standard };
const policy = {
  id: "p1",
  name: "Classrooms",
  description: "Lab computers",
  active_version_id: "v1",
  draft: null,
  draft_updated_at: null,
  versions: [{ id: "v1", sequence: 1, document: published, created_at: "2026-10-30T10:00:00", reason: "first", author: "owner", compiled: false }],
};
vi.mock("../src/hooks/useData", () => ({
  useData: (path: string) => ({
    data: path === "/policies/catalog" ? catalog : path === "/policies/p1" ? policy : path === "/policies" ? [] : null,
    error: "",
    reload: () => {},
  }),
}));
vi.mock("../src/api/client", () => ({
  ApiError: class extends Error {},
  api: vi.fn(async (path: string, _method?: string, body?: any) => {
    if (path === "/policies/validate") return { valid: true, errors: [], warnings: [], document: body.document };
    if (path === "/policies/p1/draft") return { document: body.document, draft_updated_at: "2026-10-30T11:00:00", warnings: [] };
    if (path === "/policies/p1/preview")
      return {
        changes: [{ key: "block_internet", before: true, after: false, risk: "network", automatic: false }],
        warnings: [],
        first_version: false,
        affected: { devices: 24, online: 20, offline: 4 },
      };
    return {};
  }),
}));
const mockedApi = vi.mocked(api);
beforeEach(() => mockedApi.mockClear());
afterEach(cleanup);

function renderStudio(language: Language = "en", modal = vi.fn()) {
  render(
    <LocaleContext.Provider value={{ language, setLanguage: () => {} }}>
      <WorkContext.Provider value={{ revision: 0, refresh: () => {}, modal, run: async () => {}, identity: { username: "a", role: "owner", csrf: "", mfa: true } }}>
        <PolicyStudio id="p1" />
      </WorkContext.Provider>
    </LocaleContext.Provider>,
  );
  return modal;
}

it("turns a toggle into the real policy field and saves it as a draft", async () => {
  renderStudio();
  fireEvent.click(screen.getByRole("button", { name: en["policyCategory.firewall"] }));
  const toggle = screen.getByRole("switch", { name: en["policySetting.block_internet"] });
  expect(toggle).toHaveProperty("checked", true);
  fireEvent.click(toggle);
  expect(screen.getByText(en["ps.unsaved"])).toBeTruthy();
  // The allowed-services editor only matters while the internet is blocked.
  expect(screen.queryByText(en["policySetting.firewall_allowances"])).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: en["ps.saveDraft"] }));
  await waitFor(() => expect(mockedApi).toHaveBeenCalledWith("/policies/p1/draft", "PUT", expect.anything()));
  const saved = mockedApi.mock.calls.find((c) => c[0] === "/policies/p1/draft")![2] as any;
  expect(saved.document.block_internet).toBe(false);
  expect(saved.document.firewall_allowances).toEqual(published.firewall_allowances);
  await screen.findByText(en["ps.draftSaved"]);
});

it("shows static address fields only for fixed addresses and validates them", () => {
  renderStudio();
  fireEvent.click(screen.getByRole("button", { name: en["policyCategory.network"] }));
  expect(screen.queryByLabelText(en["policySetting.ip_gateway"])).toBeNull();
  fireEvent.change(screen.getByLabelText(en["policySetting.ip_mode"]), { target: { value: "static" } });
  const gateway = screen.getByLabelText(en["policySetting.ip_gateway"]);
  fireEvent.change(gateway, { target: { value: "192.168.10.300" } });
  expect(gateway.getAttribute("aria-invalid")).toBe("true");
  expect(screen.getByText(en["policy.invalid_address"])).toBeTruthy();
  // Not-yet-implemented capabilities are visible but cannot be switched on.
  const card = screen.getByText(en["policySetting.apply_ip_configuration"]).closest("article")!;
  expect(within(card).queryByRole("switch")).toBeNull();
  expect(within(card).getAllByText(en["ps.notAvailable"]).length).toBeGreaterThan(0);
});

it("marks safety rules as always on and honest enforcement on each setting", () => {
  renderStudio();
  fireEvent.click(screen.getByRole("button", { name: en["policyCategory.disk"] }));
  const repartition = screen.getByText(en["policySetting.no_automatic_repartition"]).closest("article")!;
  expect(within(repartition).queryByRole("switch")).toBeNull();
  const required = screen.getByText(en["policySetting.require_d"]).closest("article")!;
  expect(within(required).getByText(en["enforcement.detected"])).toBeTruthy();
  fireEvent.change(screen.getByLabelText(en["ps.searchSettings"]), { target: { value: "firewall" } });
  expect(screen.getByText(en["policySetting.firewall_auto_enable"])).toBeTruthy();
});

it("reviews the change with impact before publishing", async () => {
  const modal = renderStudio();
  fireEvent.click(screen.getByRole("button", { name: en["policyCategory.firewall"] }));
  fireEvent.click(screen.getByRole("switch", { name: en["policySetting.block_internet"] }));
  fireEvent.click(screen.getByRole("button", { name: en["ps.reviewPublish"] }));
  await waitFor(() => expect(modal).toHaveBeenCalled());
  const content = modal.mock.calls.at(-1)![0].content;
  cleanup();
  render(
    <LocaleContext.Provider value={{ language: "en", setLanguage: () => {} }}>
      <WorkContext.Provider value={{ revision: 0, refresh: () => {}, modal, run: async () => {}, identity: { username: "a", role: "owner", csrf: "", mfa: true } }}>
        {content}
      </WorkContext.Provider>
    </LocaleContext.Provider>,
  );
  await screen.findByText(en["ps.affects"].replace("{n}", "24"));
  expect(screen.getByText(en["risk.network.title"])).toBeTruthy();
  const row = screen.getByText(en["policySetting.block_internet"]).closest("tr")!;
  expect(row.textContent).toContain(en["ps.on"]);
  expect(row.textContent).toContain(en["ps.off"]);
  const publish = screen.getByRole("button", { name: en.publish });
  expect(publish).toHaveProperty("disabled", true);
  fireEvent.change(screen.getByLabelText(en.reason), { target: { value: "Exam week change" } });
  expect(publish).toHaveProperty("disabled", true);
  fireEvent.click(screen.getByLabelText(en["ps.understandRisk"]));
  expect(publish).toHaveProperty("disabled", false);
});

it("renders the editor in Armenian and Russian with every catalog string translated", () => {
  for (const [language, dict] of [["hy", hy], ["ru", ru]] as const) {
    renderStudio(language);
    expect(screen.getByRole("button", { name: dict["policyCategory.accounts"] })).toBeTruthy();
    expect(screen.getByText(dict["policySetting.require_admin_account"])).toBeTruthy();
    cleanup();
  }
  const needed = [
    ...catalog.categories.flatMap((c) => [`policyCategory.${c}`, `policyCategory.${c}.hint`]),
    ...catalog.settings.flatMap((s) => [`policySetting.${s.id}`, `policySetting.${s.id}.help`, `enforcement.${s.enforcement}`, `risk.${s.risk}`]),
    ...catalog.settings.flatMap((s) => (s.options && s.control === "select" ? s.options.map((o) => `policyOption.${s.id}.${o}`) : [])),
    ...Object.keys(catalog.checks).flatMap((c) => [`check.${c}`, `check.${c}.fix`]),
  ];
  for (const dict of [en, hy, ru] as Record<string, string>[]) for (const key of needed) expect(dict[key], key).toBeTruthy();
});
