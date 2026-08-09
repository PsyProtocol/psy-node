import { chromium, expect, type BrowserContext, type Page } from "@playwright/test";
import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
export const CLI_PATH = path.join(REPO_ROOT, "target", "release", "psy_user_cli");
export const RPC_CONFIG = path.join(REPO_ROOT, "client_prover", "config.json");
export const PROFILE_DIR = path.resolve(__dirname, "..", ".profile");
export const ARTIFACTS_DIR = path.resolve(__dirname, "..", "artifacts");
export const SENDER_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
export const WALLET_PASSWORD = "ide-deploy-e2e";
export const IDE_URL = process.env.IDE_URL ?? "http://127.0.0.1:5176";
export const EXPLORER_URL = process.env.EXPLORER_URL ?? "http://127.0.0.1:5178";
export const SERVICES_URL = process.env.SERVICES_URL ?? "http://127.0.0.1:3000";
export const VOTING_CONTRACT_SOURCE = path.resolve(__dirname, "..", "fixtures", "VotingContract.psy.rs");

function walletDistDir(): string {
  if (process.env.PSY_WALLET_DIST) return path.resolve(process.env.PSY_WALLET_DIST);
  return path.resolve(REPO_ROOT, "..", "psy-wallet", "dist");
}
const WALLET_DIST_DIR = walletDistDir();

function sleep(ms: number): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, ms);
  return promise;
}

function errorText(error: unknown): string {
  if (!error || typeof error !== "object") return String(error);
  const message = "message" in error ? String(error.message) : String(error);
  const stdout = "stdout" in error ? String(error.stdout) : "";
  const stderr = "stderr" in error ? String(error.stderr) : "";
  return `${message}\n${stdout}\n${stderr}`;
}

export async function prepareDeployUser(opts?: { privateKey?: string; l2GasAmount?: string }): Promise<{ userId: number; privateKey: string }> {
  if (!fs.existsSync(CLI_PATH)) throw new Error(`psy_user_cli missing at ${CLI_PATH}`);
  const privateKey = opts?.privateKey ?? SENDER_PK;
  let combined = "";
  try {
    const result = await execFileAsync(CLI_PATH, ["register-user", "--sign-type", "zk", "-p", privateKey, "--rpc-config", RPC_CONFIG], {
      timeout: 180_000,
      maxBuffer: 4 * 1024 * 1024,
      encoding: "utf8",
    });
    combined = `${result.stdout}\n${result.stderr}`;
  } catch (error) {
    combined = errorText(error);
    if (!/already\s+registered|user[_ ]ids?/i.test(combined)) throw error;
  }
  const list = combined.match(/(?:get user ids|user_ids):\s*\[([0-9,\s]*)\]/i)?.[1];
  const userIdRaw = list?.split(/[\s,]+/).filter(Boolean)[0] ?? combined.match(/user_id[:\s]*"?(\d+)"?/i)?.[1];
  if (!userIdRaw) throw new Error(`could not parse registered user id:\n${combined.slice(0, 800)}`);
  const userId = Number(userIdRaw);

  try {
    await execFileAsync(CLI_PATH, [
      "call", "--sign-type", "zk", "-p", privateKey, "--rpc-config", RPC_CONFIG,
      "--contract-id", "0", "--method-name", "simple_mint", "--inputs", `[${opts?.l2GasAmount ?? "4000000000"}]`,
      "--wait-until-confirmation",
    ], { timeout: 180_000, maxBuffer: 4 * 1024 * 1024, encoding: "utf8" });
  } catch (error) {
    console.warn("[ide-deploy] mint warning", errorText(error).slice(0, 400));
  }
  return { userId, privateKey };
}

export class IdeWalletEnv {
  context!: BrowserContext;
  extensionId!: string;

  async launch(): Promise<this> {
    const manifest = path.join(WALLET_DIST_DIR, "manifest.json");
    if (!fs.existsSync(manifest)) throw new Error(`Psy Wallet dist missing at ${WALLET_DIST_DIR}`);
    fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
    fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
    this.context = await chromium.launchPersistentContext(PROFILE_DIR, {
      channel: "chromium",
      headless: process.env.PSY_REAL_HEADED !== "1",
      viewport: { width: 1280, height: 900 },
      args: [`--disable-extensions-except=${WALLET_DIST_DIR}`, `--load-extension=${WALLET_DIST_DIR}`],
    });
    let [worker] = this.context.serviceWorkers();
    if (!worker) worker = await this.context.waitForEvent("serviceworker", { timeout: 30_000 });
    this.extensionId = new URL(worker.url()).host;
    return this;
  }

  async openPopup(): Promise<Page> {
    const page = await this.context.newPage();
    await page.goto(`chrome-extension://${this.extensionId}/src/popup/index.html`);
    return page;
  }

  async openIde(target = "/studio"): Promise<Page> {
    const page = await this.context.newPage();
    await page.goto(`${IDE_URL}${target}`, { waitUntil: "domcontentloaded" });
    return page;
  }

  async close(): Promise<void> { await this.context?.close().catch(() => undefined); }
}

export async function onboardWallet(env: IdeWalletEnv, privateKey = SENDER_PK): Promise<void> {
  const popup = await env.openPopup();
  try {
    const password = popup.locator('input[type="password"]');
    if (await password.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await password.fill(WALLET_PASSWORD);
      await popup.getByRole("button", { name: "Unlock" }).click();
      return;
    }
    await popup.getByRole("button", { name: /Import (existing )?wallet/i }).click();
    await popup.getByRole("button", { name: /private key/i }).click();
    await popup.locator("textarea").first().fill(privateKey.replace(/^0x/, ""));
    await popup.getByRole("button", { name: /^Import Wallet$/i }).click();
    await popup.getByRole("button", { name: /ZK Wallet/i }).click();
    await popup.getByRole("button", { name: /^Continue$/ }).click();
    await popup.getByPlaceholder("please input your new password", { exact: true }).fill(WALLET_PASSWORD);
    await popup.getByPlaceholder("please input your new password again", { exact: true }).fill(WALLET_PASSWORD);
    await popup.getByRole("button", { name: /^Confirm$/ }).click();
    await expect(popup.getByText(/^(Total\s+)?Balance$/i)).toBeVisible({ timeout: 180_000 });
  } finally {
    await popup.close().catch(() => undefined);
  }
}

export async function acceptApproval(env: IdeWalletEnv, label: RegExp): Promise<void> {
  const popup = await env.context.waitForEvent("page", { timeout: 90_000 });
  try {
    const password = popup.locator('input[type="password"]').first();
    if (await password.isVisible({ timeout: 2_000 }).catch(() => false)) {
      await password.fill(WALLET_PASSWORD);
      await popup.getByRole("button", { name: /^Unlock$/ }).click();
    }
    let confirm = popup.getByRole("button", { name: label }).first();
    if (!(await confirm.isVisible({ timeout: 5_000 }).catch(() => false))) {
      confirm = popup.getByRole("button", { name: /^(Connect|Deploy|Confirm(?:\s+\d+)?|Approve|Allow)$/ }).first();
    }
    await expect(confirm).toBeVisible({ timeout: 60_000 });
    await confirm.click();
    await sleep(1_000);
  } finally {
    await popup.close().catch(() => undefined);
  }
}

export async function shot(page: Page, name: string): Promise<void> {
  fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  await page.screenshot({ path: path.join(ARTIFACTS_DIR, `${name}.png`) });
}

type UserTxItem = {
  tx_type: string | null;
  contract_id: unknown;
  eventMs: number | null;
};

function parseContractId(raw: unknown): number | null {
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;
  if (typeof raw === "string" && /^\d+$/.test(raw)) return Number(raw);
  return null;
}

function extractUserTxItems(body: unknown): UserTxItem[] {
  if (!body || typeof body !== "object" || !("data" in body)) return [];
  const data = body.data;
  if (!data || typeof data !== "object" || !("items" in data) || !Array.isArray(data.items)) return [];
  return data.items.flatMap((raw): UserTxItem[] => {
    if (!raw || typeof raw !== "object") return [];
    const txType = "tx_type" in raw && typeof raw.tx_type === "string" ? raw.tx_type : null;
    const result = "result" in raw && raw.result && typeof raw.result === "object" ? raw.result : null;
    const contractId = result && "contract_id" in result ? result.contract_id : null;
    const timestamp = ["included_at", "received_at", "timestamp"]
      .map((key) => key in raw && typeof raw[key as keyof typeof raw] === "string" ? raw[key as keyof typeof raw] as string : null)
      .find(Boolean);
    const parsedTime = timestamp ? Date.parse(timestamp) : Number.NaN;
    return [{ tx_type: txType, contract_id: contractId, eventMs: Number.isFinite(parsedTime) ? parsedTime : null }];
  });
}

export async function waitForUserDeployContractId(
  userId: number,
  startedAtMs: number,
  minContractIdExclusive: number | null = null,
  timeoutMs = 10 * 60_000,
): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const url = new URL("/api/v1/get/user/transactions", SERVICES_URL);
    url.searchParams.set("user_id", String(userId));
    url.searchParams.set("limit", "20");
    url.searchParams.set("offset", "0");
    const response = await fetch(url).catch(() => null);
    if (response?.ok) {
      const items = extractUserTxItems(await response.json());
      for (const item of items) {
        if (item.tx_type !== "deploy_contract") continue;
        const contractId = parseContractId(item.contract_id);
        if (contractId == null || (minContractIdExclusive != null && contractId <= minContractIdExclusive)) continue;
        if (item.eventMs != null && item.eventMs < startedAtMs - 10 * 60_000) continue;
        return contractId;
      }
    }
    await sleep(3_000);
  }
  throw new Error(`Timed out waiting for deploy_contract for user ${userId}`);
}

export async function deployContractViaCli(opts?: { privateKey?: string }): Promise<{ contentHash: string; methods: number; stateTreeHeight: number }> {
  const result = await execFileAsync(CLI_PATH, [
    "compile-and-deploy", "--source", VOTING_CONTRACT_SOURCE,
    "--private-key", (opts?.privateKey ?? SENDER_PK).replace(/^0x/, ""),
    "--rpc-config", RPC_CONFIG, "--sign-type", "zk",
    "--output-dir", path.join(ARTIFACTS_DIR, `deploy-${Date.now()}`),
  ], { timeout: 300_000, maxBuffer: 8 * 1024 * 1024, encoding: "utf8" });
  const combined = `${result.stdout}\n${result.stderr}`;
  const contentHash = combined.match(/Contract ID:\s*([0-9a-fA-F]{64})/)?.[1]
    ?? combined.match(/content_hash[=:\s]+([0-9a-fA-F]{64})/i)?.[1];
  if (!contentHash) throw new Error(`compile-and-deploy returned no content hash:\n${combined.slice(0, 1200)}`);
  return {
    contentHash: contentHash.toLowerCase(),
    methods: Number(combined.match(/Methods:\s*(\d+)/i)?.[1] ?? 0),
    stateTreeHeight: Number(combined.match(/State tree height:\s*(\d+)/i)?.[1] ?? 0),
  };
}

export async function waitForContractByContentHash(contentHash: string, timeoutMs = 5 * 60_000): Promise<{ contractId: number | null; uuid: string }> {
  const uuid = contentHash.replace(/^0x/, "").toLowerCase();
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const txResponse = await fetch(new URL(`/api/v1/transaction/hash/${uuid}`, SERVICES_URL)).catch(() => null);
    if (txResponse?.ok) {
      const body = await txResponse.json() as { data?: { result?: { contract_id?: number | string }; contract_id?: number | string } };
      const contractId = parseContractId(body.data?.result?.contract_id ?? body.data?.contract_id);
      if (contractId != null) return { contractId, uuid };
    }
    const contractResponse = await fetch(new URL(`/api/v1/contract/uuid/${uuid}`, SERVICES_URL)).catch(() => null);
    if (contractResponse?.ok) {
      const body = await contractResponse.json() as { data?: { contract_id?: number | string; id?: number | string } };
      return { contractId: parseContractId(body.data?.contract_id ?? body.data?.id), uuid };
    }
    await sleep(2_000);
  }
  console.warn(`[ide-deploy] indexer lag for ${uuid}; returning uuid only`);
  return { contractId: null, uuid };
}
