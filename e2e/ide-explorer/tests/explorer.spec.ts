import { expect, test } from "@playwright/test";
import { expectBodyHasText, gotoExplorer } from "../helpers/env";

test.describe("psy-explorer specialized e2e", () => {
  test("EXP-01 home renders live chain data", async ({ page }) => {
    await gotoExplorer(page);
    await expect(page).toHaveTitle(/Psy Explorer/i);
    await expectBodyHasText(page, /Psy Explorer|Search blocks/i);
    for (const label of ["Dashboard", "Blocks", "Transactions", "Contracts", "Charts"]) {
      await expect(page.getByRole("link", { name: label }).first()).toBeVisible();
    }
    await expect(page.getByText(/BLK\s*#|LIVE|Checkpoint|#\d[\d,]*/i).first()).toBeVisible();
  });

  test("EXP-02 blocks list opens detail", async ({ page }) => {
    await gotoExplorer(page, "/blocks");
    const first = page.locator('a[href*="/blocks/"]').first();
    await expect(first).toBeVisible();
    await first.click();
    await expect(page).toHaveURL(/\/blocks\/\d+/);
    await expectBodyHasText(page, /Checkpoint|Block|Height|Committed/i);
  });

  test("EXP-03 transactions page renders and opens rows when present", async ({ page }) => {
    await gotoExplorer(page, "/txs");
    await expectBodyHasText(page, /TRANSACTIONS|All Transactions/i);
    const first = page.locator('a[href*="/txs/"]').first();
    if (await first.count()) {
      await first.click();
      await expect(page).toHaveURL(/\/txs\/.+/);
      await expectBodyHasText(page, /Transaction|Invoke|Register|Deploy|Included|Status/i);
    }
  });

  test("EXP-04 contracts list opens detail", async ({ page }) => {
    await gotoExplorer(page, "/contracts");
    await expectBodyHasText(page, /faucet|usdt_token|deposit_tree|withdrawal_tree|mining_rewards/i);
    const first = page.locator('a[href*="/contracts/"]').first();
    await expect(first).toBeVisible();
    await first.click();
    await expectBodyHasText(page, /Contract|Methods|Deployer|ABI|Functions|Read|State/i);
  });

  test("EXP-05 charts and status pages", async ({ page }) => {
    await gotoExplorer(page, "/charts");
    await expectBodyHasText(page, /CHARTS|Network Activity|BLOCK TIME/i);
    await gotoExplorer(page, "/status");
    await expectBodyHasText(page, /STATUS|Network & Indexer|Chain Nodes/i);
    await expectBodyHasText(page, /COORDINATOR|REALM/i);
  });

  test("EXP-06 transactions alias", async ({ page }) => {
    await gotoExplorer(page, "/transactions");
    await expect(page).toHaveURL(/\/txs$/);
  });
});
