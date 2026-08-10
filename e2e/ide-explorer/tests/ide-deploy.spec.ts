import { expect, test } from "@playwright/test";

import {
  IdeWalletEnv,
  acceptApproval,
  deployContractViaCli,
  onboardWallet,
  prepareDeployUser,
  shot,
  waitForContractByContentHash,
  SENDER_PK,
  EXPLORER_URL,
} from "../helpers/wallet";

/**
 * On-chain deploy + IDE wallet E2E.
 *
 * IDE-05 covers CLI compile-and-deploy, Services indexing, and Explorer detail.
 * IDE-06 covers IDE compile, wallet approval, browser deploy, Services indexing,
 * and the resulting Explorer contract link.
 */

test.describe.configure({ mode: "serial" });

let env: IdeWalletEnv;
let userId = 0;

test.beforeAll(async () => {
  test.setTimeout(10 * 60_000);
  const prep = await prepareDeployUser({
    privateKey: SENDER_PK,
    l2GasAmount: "4000000000",
  });
  userId = prep.userId;
  expect(userId).toBeGreaterThan(0);
});

test.afterAll(async () => {
  await env?.close().catch(() => undefined);
});

test("IDE-05 CLI on-chain deploy VotingContract + explorer detail", async () => {
  test.setTimeout(15 * 60_000);

  // ── 1) Real on-chain deploy via CLI ──────────────────────────────────
  const deploy = await deployContractViaCli({ privateKey: SENDER_PK });
  expect(deploy.contentHash).toMatch(/^[0-9a-f]{64}$/);
  expect(deploy.methods).toBe(2);
  expect(deploy.stateTreeHeight).toBeGreaterThan(0);
  console.log("[ide-deploy] contentHash", deploy.contentHash);

  // ── 2) Indexer / services resolution ─────────────────────────────────
  const indexed = await waitForContractByContentHash(deploy.contentHash);
  expect(indexed.uuid).toBe(deploy.contentHash);
  console.log("[ide-deploy] indexed", indexed);

  // ── 3) Explorer detail for the new contract ──────────────────────────
  env = await new IdeWalletEnv().launch({ freshProfile: true });
  await onboardWallet(env, SENDER_PK);

  const explorerPage = await env.context.newPage();
  try {
    const detailPath =
      indexed.contractId != null
        ? `/contracts/${indexed.contractId}`
        : `/contracts/${indexed.uuid}`;
    await explorerPage.goto(`${EXPLORER_URL}${detailPath}`, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      explorerPage
        .getByText(
          /Contract|Methods|Deployer|VotingContract|Functions|ABI|vote|reset_voter/i,
        )
        .first(),
    ).toBeVisible({ timeout: 90_000 });
    await expect(
      explorerPage
        .getByText(
          new RegExp(
            indexed.contractId != null
              ? String(indexed.contractId)
              : indexed.uuid.slice(0, 12),
            "i",
          ),
        )
        .first(),
    ).toBeVisible({ timeout: 30_000 });
    await shot(explorerPage, "ide-deploy-explorer-detail");
  } finally {
    await explorerPage.close().catch(() => undefined);
  }
});

test("IDE-06 IDE Studio compile + real wallet deploy", async () => {
  test.setTimeout(10 * 60_000);
  env = await new IdeWalletEnv().launch({ freshProfile: true });
  await onboardWallet(env, SENDER_PK);

  const idePage = await env.openIde("/studio");
  await expect(
    idePage.getByRole("button", { name: "Studio", exact: true }),
  ).toBeVisible({ timeout: 30_000 });

  // Runtime / compile exercises the IDE path.
  const compileBtn = idePage.getByRole("button", { name: /^Compile$/ });
  await expect(compileBtn).toBeVisible({ timeout: 60_000 });
  await expect(compileBtn).toBeEnabled({ timeout: 60_000 });
  await compileBtn.click();
  await expect(idePage.getByText("Compilation successful")).toBeVisible({
    timeout: 60_000,
  });
  await shot(idePage, "ide-deploy-compiled");

  // Connect wallet through the real extension approve popup.
  const connectBtn = idePage.getByRole("button", { name: /^Connect$/ });
  await expect(connectBtn).toBeVisible({ timeout: 15_000 });
  await Promise.all([
    acceptApproval(env, /^Connect$/),
    connectBtn.click(),
  ]);

  await expect(
    idePage.getByRole("button", {
      name: new RegExp(`Psy-0*${userId}|Connected|Psy-\\d{8}`, "i"),
    }),
  ).toBeVisible({ timeout: 60_000 });
  await shot(idePage, "ide-deploy-connected");
  const deployBtn = idePage.getByRole("button", { name: /^Deploy$/ });
  await expect(deployBtn).toBeEnabled({ timeout: 10_000 });
  await Promise.all([
    acceptApproval(env, /^(?:Deploy|Confirm)$/),
    deployBtn.click(),
  ]);
  await expect(
    idePage.getByRole("link", { name: /Contract #\d+/ }),
  ).toBeVisible({ timeout: 10 * 60_000 });
  await shot(idePage, "ide-browser-deploy-confirmed");

  await idePage.close().catch(() => undefined);
});