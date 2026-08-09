import { expect, type Page } from "@playwright/test";

export const IDE_URL = process.env.IDE_URL ?? "http://127.0.0.1:5176";
export const EXPLORER_URL = process.env.EXPLORER_URL ?? "http://127.0.0.1:5178";

export async function clearOriginStorage(page: Page, origin: string): Promise<void> {
  await page.goto(origin, { waitUntil: "domcontentloaded" });
  await page.evaluate(() => {
    try { window.localStorage.clear(); window.sessionStorage.clear(); } catch { /* ignore */ }
  });
}

export async function gotoIde(page: Page, target: "landing" | "dashboard" | "studio" = "landing"): Promise<void> {
  await page.goto(target === "landing" ? `${IDE_URL}/` : `${IDE_URL}/${target}`, { waitUntil: "domcontentloaded" });
}

export async function gotoExplorer(page: Page, target = "/"): Promise<void> {
  const normalized = target.startsWith("/") ? target : `/${target}`;
  await page.goto(`${EXPLORER_URL}${normalized}`, { waitUntil: "domcontentloaded" });
}

export async function expectBodyHasText(page: Page, pattern: RegExp | string, timeout = 20_000): Promise<void> {
  await expect(page.locator("body")).toContainText(pattern, { timeout });
}
