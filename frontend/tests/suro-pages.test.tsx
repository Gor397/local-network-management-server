// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { SuroPages } from "../src/pages/SuroPages";
import { WorkContext } from "../src/context";
import { LocaleContext } from "../src/i18n";
import { api } from "../src/api/client";
import hy from "../src/locales/hy.json";

vi.mock("../src/api/client", () => ({
  api: vi.fn(async () => ({ id: "preview-1" })),
}));
vi.mock("../src/hooks/useData", () => ({
  useData: (path: string) => ({
    data:
      path === "/mikrotik/routers"
        ? [
            {
              id: "router-1",
              name: "Existing AP",
              role: "ACCESS_POINT",
              protected: false,
              write_enabled: true,
              inventory: {},
              health: {},
              recovery_policy: {
                enabled: true,
                conditions: ["unexpected_radio_disabled"],
                cooldown_seconds: 1800,
                independent_management_router_ids: ["router-2"],
              },
            },
          ]
        : path === "/packages"
          ? [
              {
                id: "firmware-approved",
                name: "Approved RouterOS",
                kind: "routeros",
                approved: true,
                metadata: { release_version: "7.21", architecture: "arm64" },
              },
              { id: "unapproved", kind: "routeros", approved: false },
              { id: "windows", kind: "msi", approved: true },
            ]
          : path.startsWith("/network/inventory")
            ? {
                total: 1,
                summary: { NOT_REGISTERED: 1 },
                items: [
                  {
                    mac: "3A:11:22:33:44:66",
                    addresses: ["192.168.88.31"],
                    hostnames: ["phone"],
                    sources: ["dhcp_lease", "arp"],
                    routers: ["Existing AP"],
                    fresh: true,
                    randomized_mac: true,
                    duplicate_address: [],
                    mikrotik_router: null,
                    device_id: null,
                    enrollment: "NOT_REGISTERED",
                    category: "UNKNOWN",
                    label: "",
                    note: "",
                  },
                ],
              }
            : path === "/mikrotik/groups"
              ? [
                  {
                    id: "floor-1",
                    name: "First floor",
                    router_ids: ["router-1"],
                    online: 1,
                    offline: 0,
                  },
                ]
              : [],
    error: "",
    reload: vi.fn(),
  }),
}));
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
function open(page = "access-points") {
  const modal = vi.fn();
  render(
    <LocaleContext.Provider value={{ language: "hy", setLanguage: () => {} }}>
      <WorkContext.Provider
        value={{
          revision: 0,
          refresh: vi.fn(),
          modal,
          run: async (fn) => {
            await fn();
          },
          identity: {
            username: "owner",
            role: "owner",
            csrf: "test",
            mfa: false,
          },
        }}
      >
        <SuroPages page={page} id="router-1" />
      </WorkContext.Provider>
    </LocaleContext.Provider>,
  );
  return modal;
}
it("changing SSID leaves radio enabled/disabled state unchanged by default", async () => {
  const modal = open();
  fireEvent.click(screen.getByRole("button", { name: hy.wireless }));
  const spec = modal.mock.calls[0][0];
  expect(spec.fields.find((f: any) => f.name === "disabled").value).toBe(
    "unchanged",
  );
  await spec.submit({
    stack: "wifi",
    interface: "wifi1",
    ssid: "Գրասենյակ",
    disabled: "unchanged",
    reason: "Reviewed lab change",
    batch_size: 1,
    stop_on_failure: true,
  });
  const payload = vi.mocked(api).mock.calls[0][2] as any;
  expect(payload.parameters.ssid).toBe("Գրասենյակ");
  expect(payload.parameters).not.toHaveProperty("disabled");
});
it("renaming infrastructure does not clear its existing pinned SSH key", async () => {
  const modal = open();
  fireEvent.click(screen.getByRole("button", { name: hy.editDevice }));
  const spec = modal.mock.calls[0][0];
  await spec.submit({
    name: "Renamed AP",
    role: "ACCESS_POINT",
    protected: false,
    ssh_host_key: "",
  });
  const payload = vi.mocked(api).mock.calls[0][2] as any;
  expect(payload.name).toBe("Renamed AP");
  expect(payload).not.toHaveProperty("ssh_host_key");
});
it("offers only approved router packages in the firmware picker", () => {
  const modal = open();
  fireEvent.click(screen.getByRole("button", { name: hy.upgrade }));
  const spec = modal.mock.calls[0][0],
    field = spec.fields.find((f: any) => f.name === "package_id");
  expect(field.type).toBe("select");
  expect(field.options.map((o: any) => o.value)).toEqual(["firmware-approved"]);
});
it("keeps group diagnostics scoped to the selected AP group", async () => {
  const modal = open("ap-groups");
  fireEvent.change(screen.getByLabelText(hy.actions), {
    target: { value: "diagnostics" },
  });
  const spec = modal.mock.calls[0][0];
  await spec.submit({
    reason: "Approved fixture diagnostics",
    batch_size: 1,
    stop_on_failure: true,
  });
  const payload = vi.mocked(api).mock.calls[0][2] as any;
  expect(payload.group_id).toBe("floor-1");
  expect(payload.router_ids).toEqual([]);
  expect(payload.operation).toBe("diagnostics");
});
it("preserves configured recovery options and submits typed selected conditions", async () => {
  const modal = open("recovery-settings");
  fireEvent.click(screen.getByRole("button", { name: hy.configureRecovery }));
  const spec = modal.mock.calls[0][0];
  expect(spec.fields.find((f: any) => f.name === "enabled").value).toBe(true);
  expect(spec.fields.find((f: any) => f.name === "recover_radio").value).toBe(
    true,
  );
  expect(
    spec.fields.find((f: any) => f.name === "recover_resources").value,
  ).toBe(false);
  expect(
    spec.fields.find((f: any) => f.name === "cooldown_seconds").value,
  ).toBe(1800);
  await spec.submit({
    enabled: true,
    recover_radio: true,
    recover_resources: false,
    independent_management_router_ids: '["router-2"]',
  });
  const payload = vi.mocked(api).mock.calls[0][2] as any;
  expect(payload.conditions).toEqual(["unexpected_radio_disabled"]);
  expect(payload.independent_management_router_ids).toEqual(["router-2"]);
});

it("network inventory shows Armenian states and classifies through the label API only", async () => {
  const modal = open("network-inventory");
  expect(screen.getAllByText(hy.NOT_REGISTERED).length).toBeGreaterThan(0);
  expect(screen.getByText(hy.randomMac)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: hy.classify }));
  const spec = modal.mock.calls[0][0];
  expect(spec.fields[0].options.map((o: any) => o.label)).toContain(
    hy.cat_PRINTER,
  );
  await spec.submit({ category: "PRINTER", label: "Տպիչ", note: "" });
  expect(vi.mocked(api).mock.calls[0].slice(0, 2)).toEqual([
    "/network/inventory/3A%3A11%3A22%3A33%3A44%3A66/label",
    "PUT",
  ]);
});
