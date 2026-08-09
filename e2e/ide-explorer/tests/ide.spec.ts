import { expect, test } from "@playwright/test";
import { clearOriginStorage, expectBodyHasText, gotoIde, IDE_URL } from "../helpers/env";

test.describe("ide specialized e2e", () => {
  test.beforeEach(async ({ page }) => clearOriginStorage(page, IDE_URL));

  test("IDE-01 landing opens Studio", async ({ page }) => {
    await gotoIde(page);
    await expect(page).toHaveTitle(/Psy Developer Platform/);
    await expect(page.locator("h1")).toContainText(/Build, deploy, and prove/);
    await page.getByRole("link", { name: "Open the IDE" }).first().click();
    await expect(page).toHaveURL(`${IDE_URL}/studio`);
    await expectBodyHasText(page, /Compile|Loading runtime/i);
  });

  test("IDE-02 dashboard templates open in Studio", async ({ page }) => {
    await gotoIde(page, "dashboard");
    await expect(page.getByText("HelloStorageContract").first()).toBeVisible();
    await expect(page.getByText("CounterContract").first()).toBeVisible();
    await page.getByRole("button", { name: "Open in Studio" }).first().click();
    await expect(page).toHaveURL(`${IDE_URL}/studio`);
  });

  test("IDE-03 real WASM runtime compiles default project", async ({ page }) => {
    await gotoIde(page, "studio");
    const compile = page.getByRole("button", { name: /^Compile$/ });
    await expect(compile).toBeEnabled({ timeout: 60_000 });
    await compile.click();
    await expect(page.getByText("Compilation successful")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText("Compiler Output")).toBeVisible();
  });

  test("IDE-04 clean Projects and Studio routes", async ({ page }) => {
    await gotoIde(page, "studio");
    await page.getByRole("button", { name: "Projects", exact: true }).click();
    await expect(page).toHaveURL(`${IDE_URL}/dashboard`);
    await page.getByRole("button", { name: "Studio", exact: true }).click();
    await expect(page).toHaveURL(`${IDE_URL}/studio`);
  });
});
