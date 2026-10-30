// @vitest-environment jsdom
import { afterEach, describe, it, expect } from "vitest";
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import {
  LocaleContext,
  DEFAULT_LANGUAGE,
  initialLanguage,
  type Language,
} from "../src/i18n";
import { HelpButton, HelpCenter } from "../src/components/Help";
import { helpCatalogs } from "../src/help/catalog";

afterEach(() => {
  cleanup();
  localStorage.clear();
});
function locale(language: Language, component: React.ReactNode) {
  return (
    <LocaleContext.Provider value={{ language, setLanguage: () => {} }}>
      {component}
    </LocaleContext.Provider>
  );
}
describe("Suro contextual help", () => {
  it("defaults to Armenian and preserves an explicitly chosen language", () => {
    expect(DEFAULT_LANGUAGE).toBe("hy");
    expect(initialLanguage()).toBe("hy");
    localStorage.setItem("lantern-language", "ru");
    expect(initialLanguage()).toBe("ru");
    localStorage.setItem("lantern-language", "invalid");
    expect(initialLanguage()).toBe("hy");
  });
  for (const language of ["hy", "ru", "en"] as Language[]) {
    it(`opens and closes a real contextual explanation in ${language}`, () => {
      render(locale(language, <HelpButton id="reboot" />));
      fireEvent.click(screen.getByRole("button"));
      expect(screen.getByRole("dialog").textContent).toContain(
        helpCatalogs[language].articles.reboot.body,
      );
      const buttons = screen.getAllByRole("button");
      fireEvent.click(buttons[buttons.length - 1]);
      expect(screen.queryByRole("dialog")).toBeNull();
    });
    it(`searches native help content in ${language}`, () => {
      render(locale(language, <HelpCenter />));
      const query = helpCatalogs[language].articles.dhcp.title;
      fireEvent.change(screen.getByRole("textbox"), {
        target: { value: query },
      });
      expect(screen.getByRole("heading", { level: 2 }).textContent).toBe(query);
    });
  }
  it("has complete versioned help with native translations, not English fallbacks", () => {
    const keys = Object.keys(helpCatalogs.en.articles).sort();
    for (const l of ["hy", "ru", "en"] as Language[])
      expect(Object.keys(helpCatalogs[l].articles).sort()).toEqual(keys);
    for (const key of keys) {
      const id = key as keyof typeof helpCatalogs.en.articles;
      expect(helpCatalogs.hy.articles[id].body).toMatch(/[\u0530-\u058f]/);
      expect(helpCatalogs.ru.articles[id].body).toMatch(/[\u0400-\u04ff]/);
      expect(helpCatalogs.hy.articles[id].body).not.toBe(
        helpCatalogs.en.articles[id].body,
      );
    }
  });
});
