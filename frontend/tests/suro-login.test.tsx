// @vitest-environment jsdom
import { afterEach, it, expect, vi } from "vitest";
import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from "@testing-library/react";
import App from "../src/App";
import hy from "../src/locales/hy.json";

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});
it("brands the login Suro, defaults to Armenian and leaves OTP optional", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(JSON.stringify({ error: { code: "auth.required" } }), {
          status: 401,
          headers: { "content-type": "application/json" },
        }),
    ),
  );
  render(<App />);
  expect(
    await screen.findByRole("heading", { name: hy.loginTitle }),
  ).toBeTruthy();
  expect(document.documentElement.lang).toBe("hy");
  expect(screen.getByText("Suro")).toBeTruthy();
  expect(document.querySelector('input[name="totp"]')).toBeNull();
  const username = screen.getByLabelText(hy.username),
    password = screen.getByLabelText(hy.password);
  expect(username).toBeTruthy();
  expect(password).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: hy.optionalOtp }));
  expect(document.querySelector('input[name="totp"]')).toBeTruthy();
  expect(
    (document.querySelector('input[name="totp"]') as HTMLInputElement).required,
  ).toBe(false);
});
