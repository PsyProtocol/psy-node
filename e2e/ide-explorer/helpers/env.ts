import { expect, type Page } from "@playwright/test";

export const IDE_URL = process.env.IDE_URL ?? "http://127.0.0.1:5176";
export const EXPLORER_URL =
  process.env.EXPLORER_URL ?? "http://127.0.0.1:5178";

/** Clear origin storage so IDE defaults (template projects) are deterministic. */
export async function clearOriginStorage(page: Page, origin: string): Promise<void> {
  await page.goto(origin, { waitUntil: "domcontentloaded" });
  await page.evaluate(() => {
    try {
      window.localStorage.clear();
      window.sessionStorage.clear();
    } catch {
      /* ignore */
    }
  });
}

export async function gotoIde(
  page: Page,
  path: "landing" | "dashboard" | "studio" = "landing",
): Promise<void> {
  // Clean History-API routes (see frontend/src/router.ts urlFor()): the
  // landing is the bare root '/' and IDE surfaces are path-style.
  const url = path === "landing" ? `${IDE_URL}/` : `${IDE_URL}/${path}`;
  await page.goto(url, { waitUntil: "domcontentloaded" });
}
export async function gotoExplorer(page: Page, path = "/"): Promise<void> {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  await page.goto(`${EXPLORER_URL}${normalized}`, {
    waitUntil: "domcontentloaded",
  });
}

/** Wait until the page body has non-trivial content (SPA settled). */
export async function expectBodyHasText(
  page: Page,
  pattern: RegExp | string,
  timeout = 20_000,
): Promise<void> {
  await expect(page.locator("body")).toContainText(pattern, { timeout });
}
