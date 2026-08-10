import { expect, test } from "@playwright/test";

import { expectBodyHasText, gotoExplorer } from "../helpers/env";

/**
 * Specialized Psy Explorer E2E against a live local stack.
 *
 * Contract:
 *  1. Home dashboard renders live metrics / activity
 *  2. Primary nav routes load list pages with real data
 *  3. Blocks / txs / contracts list → detail navigation works
 *  4. Status page reports chain node health
 *  5. Search can resolve a known checkpoint id
 *
 * No wallet connect required. Accepts "STAGING" or "Degraded" health pill
 * as long as pages render real chain content.
 */

test.describe("psy-explorer specialized e2e", () => {
  test("EXP-01 home: search, live ticker, dashboard metrics", async ({
    page,
  }) => {
    await gotoExplorer(page, "/");
    await expect(page).toHaveTitle(/Psy Explorer/i);
    await expectBodyHasText(page, /Psy Explorer|Search blocks/i);

    // Primary nav
    for (const label of [
      "Dashboard",
      "Blocks",
      "Transactions",
      "Contracts",
      "Charts",
    ]) {
      await expect(page.getByRole("link", { name: label }).first()).toBeVisible();
    }

    // Live block ticker or checkpoint signal
    await expect(
      page.getByText(/BLK\s*#|LIVE|Checkpoint|#\d[\d,]*/i).first(),
    ).toBeVisible({ timeout: 20_000 });
  });

  test("EXP-02 blocks list and detail", async ({ page }) => {
    await gotoExplorer(page, "/blocks");
    await expectBodyHasText(page, /BLOCKS|Checkpoints|Block Height/i);

    // List must show at least one checkpoint row
    const firstBlock = page.locator('a[href*="/blocks/"]').first();
    await expect(firstBlock).toBeVisible({ timeout: 20_000 });
    const label = (await firstBlock.textContent())?.trim() ?? "";
    expect(label.length).toBeGreaterThan(0);

    await firstBlock.click();
    await expect(page).toHaveURL(/\/blocks\/\d+/);

    // Detail: not a permanent loading skeleton
    await expect(
      page.getByText(/Checkpoint|Block|Height|Committed|Users|Contracts/i).first(),
    ).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText(/Transaction Not Found|Not Found/i)).toHaveCount(
      0,
    );
  });

  test("EXP-03 transactions list and detail", async ({ page }) => {
    await gotoExplorer(page, "/txs");
    await expectBodyHasText(page, /TRANSACTIONS|All Transactions/i);

    const firstTx = page.locator('a[href*="/txs/"]').first();
    // Fresh chains may temporarily have no txs — still require the list chrome.
    if ((await firstTx.count()) === 0) {
      await expectBodyHasText(page, /transaction/i);
      test.info().annotations.push({
        type: "note",
        description: "no tx rows yet; list page still rendered",
      });
      return;
    }

    await expect(firstTx).toBeVisible({ timeout: 20_000 });
    await firstTx.click();
    await expect(page).toHaveURL(/\/txs\/.+/);
    await expect(
      page.getByText(/Transaction|Invoke|Register|Deploy|Included|Status|User/i).first(),
    ).toBeVisible({ timeout: 20_000 });
    await expect(page.getByText("Transaction Not Found")).toHaveCount(0);
  });

  test("EXP-04 contracts list and detail", async ({ page }) => {
    await gotoExplorer(page, "/contracts");
    await expectBodyHasText(page, /CONTRACTS|Deployed Contracts/i);

    const firstContract = page.locator('a[href*="/contracts/"]').first();
    await expect(firstContract).toBeVisible({ timeout: 20_000 });
    // Local genesis deploys should always expose faucet / deposit_tree etc.
    await expectBodyHasText(page, /faucet|usdt_token|deposit_tree|withdrawal_tree|mining_rewards/i);

    await firstContract.click();
    await expect(page).toHaveURL(/\/contracts\/.+/);
    await expect(
      page.getByText(/Contract|Methods|Deployer|ABI|Functions|Read|State/i).first(),
    ).toBeVisible({ timeout: 20_000 });
  });

  test("EXP-05 charts and status pages", async ({ page }) => {
    await gotoExplorer(page, "/charts");
    await expectBodyHasText(page, /CHARTS|Network Activity|BLOCK TIME/i);

    await gotoExplorer(page, "/status");
    await expectBodyHasText(page, /STATUS|Network & Indexer|Chain Nodes/i);
    await expectBodyHasText(page, /COORDINATOR|REALM/i);
    // At least coordinator URL should surface in status
    await expect(page.getByText(/127\.0\.0\.1:1337|coordinator/i).first()).toBeVisible({
      timeout: 20_000,
    });
  });

  test("EXP-06 nav + /transactions alias redirect", async ({ page }) => {
    await gotoExplorer(page, "/");
    await page.getByRole("link", { name: "Blocks" }).first().click();
    await expect(page).toHaveURL(/\/blocks/);

    await page.getByRole("link", { name: "Transactions" }).first().click();
    await expect(page).toHaveURL(/\/txs/);

    await page.getByRole("link", { name: "Contracts" }).first().click();
    await expect(page).toHaveURL(/\/contracts/);

    // Friendly alias
    await gotoExplorer(page, "/transactions");
    await expect(page).toHaveURL(/\/txs$/);
  });

  test("EXP-07 search resolves a checkpoint id", async ({ page }) => {
    await gotoExplorer(page, "/blocks");
    const firstBlock = page.locator('a[href*="/blocks/"]').first();
    await expect(firstBlock).toBeVisible({ timeout: 20_000 });
    const href = await firstBlock.getAttribute("href");
    const id = href?.match(/\/blocks\/(\d+)/)?.[1];
    expect(id).toBeTruthy();

    await gotoExplorer(page, "/");
    // Prefer the main search input; fall back to command-palette trigger.
    const search = page.locator('input[placeholder*="Search" i], input[type="search"]').first();
    if ((await search.count()) > 0) {
      await search.fill(String(id));
      await search.press("Enter");
    } else {
      // Open palette with the visible Search control if present
      const trigger = page.getByRole("button", { name: /Search/i }).first();
      if ((await trigger.count()) > 0) await trigger.click();
      const paletteInput = page.locator("input").first();
      await paletteInput.fill(String(id));
      await paletteInput.press("Enter");
    }

    // Either navigates to the block detail or shows a search hit we can click.
    const detail = page.waitForURL(new RegExp(`/blocks/${id}`), {
      timeout: 15_000,
    });
    const hit = page
      .locator(`a[href*="/blocks/${id}"]`)
      .first()
      .click({ timeout: 15_000 })
      .then(() => page.waitForURL(new RegExp(`/blocks/${id}`), { timeout: 10_000 }));

    await Promise.any([detail, hit]);

    await expect(page).toHaveURL(new RegExp(`/blocks/${id}`));
    await expect(
      page.getByText(new RegExp(`#?${id}|Checkpoint|Block`, "i")).first(),
    ).toBeVisible({ timeout: 20_000 });
  });
});
