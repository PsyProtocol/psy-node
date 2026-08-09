import { expect, test } from "@playwright/test";
import {
  IdeWalletEnv,
  acceptApproval,
  deployContractViaCli,
  onboardWallet,
  prepareDeployUser,
  shot,
  waitForContractByContentHash,
  waitForUserDeployContractId,
  SENDER_PK,
  EXPLORER_URL,
} from "../helpers/wallet";

test.describe.configure({ mode: "serial" });
let env: IdeWalletEnv;
let userId = 0;

test.beforeAll(async () => {
  const prep = await prepareDeployUser({ privateKey: SENDER_PK, l2GasAmount: "4000000000" });
  userId = prep.userId;
  expect(userId).toBeGreaterThan(0);
});

test.afterAll(async () => env?.close());

test("IDE-05 CLI deploy is indexed and visible in Explorer", async () => {
  const deploy = await deployContractViaCli({ privateKey: SENDER_PK });
  expect(deploy.contentHash).toMatch(/^[0-9a-f]{64}$/);
  expect(deploy.methods).toBe(2);
  const indexed = await waitForContractByContentHash(deploy.contentHash);
  env = await new IdeWalletEnv().launch();
  await onboardWallet(env, SENDER_PK);
  const page = await env.context.newPage();
  const detail = indexed.contractId == null ? `/contracts/${indexed.uuid}` : `/contracts/${indexed.contractId}`;
  await page.goto(`${EXPLORER_URL}${detail}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText(/Contract|Methods|Deployer|VotingContract|Functions|ABI|vote|reset_voter/i).first()).toBeVisible({ timeout: 90_000 });
  await shot(page, "ide-deploy-explorer-detail");
});

test("IDE-06 Studio compiles and deploys through the real wallet", async () => {
  test.setTimeout(10 * 60_000);
  env = await new IdeWalletEnv().launch();
  await onboardWallet(env, SENDER_PK);
  const page = await env.openIde("/studio");
  const compile = page.getByRole("button", { name: /^Compile$/ });
  await expect(compile).toBeEnabled({ timeout: 60_000 });
  await compile.click();
  await expect(page.getByText("Compilation successful")).toBeVisible({ timeout: 60_000 });
  const connect = page.getByRole("button", { name: /^Connect$/ });
  await Promise.all([acceptApproval(env, /^Connect$/), connect.click()]);
  await expect(page.getByRole("button", { name: new RegExp(`Psy-0*${userId}|Connected|Psy-\\d{8}`, "i") })).toBeVisible({ timeout: 60_000 });
  const deploy = page.getByRole("button", { name: /^Deploy$/ });
  const startedAt = Date.now();
  await Promise.all([acceptApproval(env, /^(?:Deploy|Confirm)$/), deploy.click()]);
  const link = page.getByRole("link", { name: /Contract #\d+/ });
  if (!(await link.isVisible({ timeout: 30_000 }).catch(() => false))) {
    const contractId = await waitForUserDeployContractId(userId, startedAt);
    await expect(page.getByRole("link", { name: new RegExp(`Contract #${contractId}`) })).toBeVisible({ timeout: 10 * 60_000 });
  }
  await shot(page, "ide-browser-deploy-confirmed");
});
