import { expect, test } from "@playwright/test";

import {
  clearOriginStorage,
  expectBodyHasText,
  gotoIde,
  IDE_URL,
} from "../helpers/env";

/**
 * Specialized IDE E2E (no wallet, no deploy).
 *
 * Contract:
 *  1. Landing renders and routes into Studio / Projects
 *  2. Dashboard lists default template projects
 *  3. Studio loads default project + Monaco editor
 *  4. WASM runtime becomes ready and Compile succeeds for HelloStorageContract
 */
test.describe("ide specialized e2e", () => {
  test.beforeEach(async ({ page }) => {
    await clearOriginStorage(page, IDE_URL);
  });

  test("IDE-01 landing: Psy Developer Platform hero opens Studio", async ({
    page,
  }) => {
    await gotoIde(page);
    await expect(page).toHaveTitle(/Psy Developer Platform/);
    await expect(page.locator("h1")).toContainText(/Build, deploy, and prove/);
    await expect(page.locator("h1")).toContainText(/ZK-native chain/);
    await expect(
      page.getByRole("link", { name: "Start with PsyUp" }),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "Read the docs" }),
    ).toBeVisible();
    // The Web IDE pillar card links straight into the Studio route.
    await expect(
      page.getByRole("link", { name: "Open the IDE" }).first(),
    ).toBeVisible();

    await page.getByRole("link", { name: "Open the IDE" }).first().click();
    await expect(page).toHaveURL(`${IDE_URL}/studio`);
    await expectBodyHasText(page, /Compile|Loading runtime/i);
  });

  test("IDE-02 dashboard: default projects open in Studio", async ({
    page,
  }) => {
    await gotoIde(page, "dashboard");
    await expectBodyHasText(page, /Projects/i);
    await expect(page.getByText("HelloStorageContract").first()).toBeVisible({
      timeout: 20_000,
    });
    await expect(page.getByText("CounterContract").first()).toBeVisible();
    await expect(page.getByText("PsyTokenLite").first()).toBeVisible();

    await page
      .getByRole("button", { name: "Open in Studio" })
      .first()
      .click();
    await expect(page).toHaveURL(`${IDE_URL}/studio`);
    await expectBodyHasText(page, /HelloStorageContract|main\.psy/i);
  });

  test("IDE-03 studio: runtime ready and compile HelloStorage succeeds", async ({
    page,
  }) => {
    await gotoIde(page, "studio");

    // Studio chrome
    await expect(page.getByRole("button", { name: "Projects" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Studio" })).toBeVisible();
    await expectBodyHasText(page, /main\.psy|HelloStorageContract/i);

    // Wait for WASM runtime — button flips from "Loading runtime..." to "Compile".
    const compileBtn = page.getByRole("button", { name: /^Compile$/ });
    await expect(compileBtn).toBeVisible({ timeout: 60_000 });
    await expect(compileBtn).toBeEnabled({ timeout: 60_000 });

    await compileBtn.click();

    // Bottom panel Compiler Output
    await expect(page.getByText("Compilation successful")).toBeVisible({
      timeout: 60_000,
    });
    // ABI details from successful compile
    await expect(page.getByText(/HelloStorageContract/i).first()).toBeVisible();
    await expect(page.getByText("Compiler Output")).toBeVisible();
  });

  test("IDE-04 nav clean paths: Projects ↔ Studio", async ({ page }) => {
    await gotoIde(page, "studio");
    await expectBodyHasText(page, /Compile|Loading runtime/i);

    await page.getByRole("button", { name: "Projects", exact: true }).click();
    await expect(page).toHaveURL(`${IDE_URL}/dashboard`);
    await expectBodyHasText(page, /Local IDE projects/i);

    // Nav "Studio" only — project cards also expose "Open in Studio".
    await page.getByRole("button", { name: "Studio", exact: true }).click();
    await expect(page).toHaveURL(`${IDE_URL}/studio`);
    await expectBodyHasText(page, /Compile|Loading runtime|Deploy/i);
  });
});
