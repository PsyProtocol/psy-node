import {
  chromium,
  expect,
  type BrowserContext,
  type Page,
} from "@playwright/test";
import { execFile } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
export const CLI_PATH = path.join(
  REPO_ROOT,
  "target",
  "release",
  "psy_user_cli",
);
export const RPC_CONFIG = path.join(REPO_ROOT, "psy-genesis", "config.json");
export const PROFILE_DIR = path.resolve(__dirname, "..", ".profile");
export const ARTIFACTS_DIR = path.resolve(__dirname, "..", "artifacts");

/** Anvil account #0 — matches bridge real e2e. */
export const SENDER_PK =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
export const SENDER_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
export const WALLET_PASSWORD = "ide-deploy-e2e";

export const IDE_URL = process.env.IDE_URL ?? "http://127.0.0.1:5176";
export const EXPLORER_URL =
  process.env.EXPLORER_URL ?? "http://127.0.0.1:5178";
export const SERVICES_URL =
  process.env.SERVICES_URL ?? "http://127.0.0.1:3000";

function resolveWalletDistDir(): string {
  if (process.env.PSY_WALLET_DIST) {
    return path.resolve(process.env.PSY_WALLET_DIST);
  }
  let dir = __dirname;
  for (let i = 0; i < 8; i += 1) {
    const candidate = path.join(dir, "psy-wallet", "dist");
    if (fs.existsSync(path.join(candidate, "manifest.json"))) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.resolve(REPO_ROOT, "..", "psy-wallet", "dist");
}

export const WALLET_DIST_DIR = resolveWalletDistDir();

export function assertWalletDist(): void {
  const manifest = path.join(WALLET_DIST_DIR, "manifest.json");
  if (!fs.existsSync(manifest)) {
    throw new Error(
      `Psy Wallet dist missing at ${WALLET_DIST_DIR}. Build with ` +
        `\`cd ../psy-wallet && vite build --mode dev\` or set PSY_WALLET_DIST.`,
    );
  }
}

export function assertCli(): void {
  if (!fs.existsSync(CLI_PATH)) {
    throw new Error(
      `psy_user_cli missing at ${CLI_PATH}. Build with ` +
        `\`cargo build --release -p psy_user_cli\`.`,
    );
  }
}

function sleep(ms: number): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setTimeout(resolve, ms);
  return promise;
}

function execErrorParts(err: unknown): {
  stdout: string;
  stderr: string;
  message: string;
} {
  if (!err || typeof err !== "object") {
    return { stdout: "", stderr: "", message: String(err) };
  }
  return {
    stdout: "stdout" in err && typeof err.stdout === "string" ? err.stdout : "",
    stderr: "stderr" in err && typeof err.stderr === "string" ? err.stderr : "",
    message:
      "message" in err && typeof err.message === "string"
        ? err.message
        : String(err),
  };
}

function parseUserIdFromRegisterOutput(combined: string): number {
  const listMatch = combined.match(
    /(?:get user ids|user_ids):\s*\[([0-9,\s]*)\]/i,
  );
  const firstFromList = listMatch?.[1]?.split(/[\s,]+/).filter(Boolean)[0];
  const echoMatch = combined.match(/user_id[:\s]*"?(\d+)"?/i);
  const firstUserId = firstFromList ?? echoMatch?.[1];
  if (!firstUserId) {
    throw new Error(
      `register-user: could not parse user_id from:\n${combined.slice(0, 800)}`,
    );
  }
  return Number(firstUserId);
}

/** Register user (idempotent) and mint L2 PSY gas for deploy fees. */
export async function prepareDeployUser(opts?: {
  privateKey?: string;
  l2GasAmount?: string;
}): Promise<{ userId: number; privateKey: string }> {
  assertCli();
  const privateKey = opts?.privateKey ?? SENDER_PK;
  const args = [
    "register-user",
    "--sign-type",
    "zk",
    "-p",
    privateKey,
    "--rpc-config",
    RPC_CONFIG,
  ];

  let stdout = "";
  let stderr = "";
  try {
    const out = await execFileAsync(CLI_PATH, args, {
      timeout: 180_000,
      maxBuffer: 4 * 1024 * 1024,
      encoding: "utf8",
    });
    stdout = out.stdout;
    stderr = out.stderr;
  } catch (err: unknown) {
    const parts = execErrorParts(err);
    const combined = `${parts.stdout}\n${parts.stderr}`;
    if (
      /already\s+registered|user_id|user ids|skip registration/i.test(combined)
    ) {
      stdout = parts.stdout;
      stderr = parts.stderr;
    } else {
      throw new Error(`register-user failed: ${parts.message}\n${combined}`);
    }
  }

  const userId = parseUserIdFromRegisterOutput(`${stdout}\n${stderr}`);
  const amount = opts?.l2GasAmount ?? "4000000000";
  const mintArgs = [
    "call",
    "--sign-type",
    "zk",
    "-p",
    privateKey,
    "--rpc-config",
    RPC_CONFIG,
    "--contract-id",
    "0",
    "--method-name",
    "simple_mint",
    "--inputs",
    `[${amount}]`,
    "--wait-until-confirmation",
  ];

  const mintDeadline = Date.now() + 120_000;
  while (true) {
    try {
      await execFileAsync(CLI_PATH, mintArgs, {
        timeout: 180_000,
        maxBuffer: 4 * 1024 * 1024,
        encoding: "utf8",
      });
      break;
    } catch (err: unknown) {
      const parts = execErrorParts(err);
      const combinedMint = `${parts.stdout}\n${parts.stderr}\n${parts.message}`;
      if (/confirmed|included|success/i.test(combinedMint)) break;
      if (
        Date.now() < mintDeadline &&
        (/no user ids found|not registered/i.test(combinedMint) ||
          combinedMint.trim() === "")
      ) {
        await sleep(5_000);
        continue;
      }
      // Non-fatal: prior runs may already hold gas.
      console.warn("[ide-deploy] mint warning:", combinedMint.slice(0, 400));
      break;
    }
  }

  return { userId, privateKey };
}

export class IdeWalletEnv {
  context!: BrowserContext;
  extensionId!: string;

  async launch(opts: { freshProfile?: boolean } = {}): Promise<this> {
    assertWalletDist();
    if (opts.freshProfile !== false) {
      fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
    }
    fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });

    this.context = await chromium.launchPersistentContext(PROFILE_DIR, {
      channel: "chromium",
      headless: process.env.PSY_REAL_HEADED === "1" ? false : true,
      viewport: { width: 1280, height: 900 },
      args: [
        `--disable-extensions-except=${WALLET_DIST_DIR}`,
        `--load-extension=${WALLET_DIST_DIR}`,
        "--enable-logging=stderr",
        "--v=0",
      ],
    });

    let [sw] = this.context.serviceWorkers();
    if (!sw) {
      sw = await this.context.waitForEvent("serviceworker", {
        timeout: 30_000,
      });
    }
    this.extensionId = new URL(sw.url()).host;
    return this;
  }

  popupUrl(): string {
    return `chrome-extension://${this.extensionId}/src/popup/index.html`;
  }

  async openPopup(): Promise<Page> {
    const page = await this.context.newPage();
    await page.goto(this.popupUrl());
    return page;
  }

  async openIde(path = "/studio"): Promise<Page> {
    const page = await this.context.newPage();
    await page.goto(`${IDE_URL}${path}`, {
      waitUntil: "domcontentloaded",
    });
    return page;
  }

  async close(): Promise<void> {
    await this.context?.close().catch(() => undefined);
  }
}

/** Re-resolve confirmation buttons because extension popup renders replace their DOM nodes. */
async function clickConfirmation(
  popup: Page,
  label: RegExp,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    const remaining = Math.max(1, deadline - Date.now());
    const confirm = popup.getByRole("button", { name: label }).first();
    try {
      await expect(confirm).toBeVisible({ timeout: remaining });
      await expect(confirm).toBeEnabled({ timeout: remaining });
      // Bounded click attempt: covers a brief detach/rerender, then re-gate.
      await confirm.click({ timeout: Math.min(10_000, remaining) });
      return;
    } catch (err: unknown) {
      lastError = err;
    }
  }
  if (lastError instanceof Error) throw lastError;
  throw new Error("clickConfirmation timed out");
}

export async function onboardWallet(
  env: IdeWalletEnv,
  privateKey = SENDER_PK,
): Promise<void> {
  const popup = await env.openPopup();
  try {
    await popup.waitForLoadState("domcontentloaded");
    const unlockInput = popup.locator('input[type="password"]');
    const totalBalance = popup.getByText(/^(Total\s+)?Balance$/i);
    const welcome = popup.getByText(
      /Welcome to Psy Wallet|Set up Psy Wallet/i,
    );

    let state: "unlocked" | "locked" | "welcome" | "unknown" = "unknown";
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline && state === "unknown") {
      if (await totalBalance.isVisible().catch(() => false)) state = "unlocked";
      else if (await unlockInput.isVisible().catch(() => false))
        state = "locked";
      else if (await welcome.isVisible().catch(() => false)) state = "welcome";
      else await popup.waitForTimeout(1_000);
    }

    if (state === "unlocked") return;
    if (state === "locked") {
      await unlockInput.fill(WALLET_PASSWORD);
      await popup.getByRole("button", { name: "Unlock" }).click();
      await expect(totalBalance).toBeVisible({ timeout: 120_000 });
      return;
    }
    expect(state).toBe("welcome");

    await popup
      .getByRole("button", { name: /Import (existing )?wallet/i })
      .click();
    await popup.getByRole("button", { name: /private key/i }).click();
    await popup
      .locator("textarea")
      .first()
      .fill(privateKey.replace(/^0x/, ""));
    await popup.getByRole("button", { name: /^Import Wallet$/i }).click();
    await popup.getByRole("button", { name: /ZK Wallet/i }).click();
    await popup.getByRole("button", { name: /^Continue$/ }).click();

    const newPwd = popup.getByPlaceholder("please input your new password", {
      exact: true,
    });
    await newPwd.waitFor({ state: "visible", timeout: 120_000 });
    await newPwd.fill(WALLET_PASSWORD);
    await popup
      .getByPlaceholder("please input your new password again", {
        exact: true,
      })
      .fill(WALLET_PASSWORD);
    await clickConfirmation(popup, /^Confirm$/, 120_000);
    await expect(totalBalance).toBeVisible({ timeout: 180_000 });
  } finally {
    await popup.close().catch(() => undefined);
  }
}

async function unlockIfNeeded(popup: Page): Promise<void> {
  const password = popup.locator('input[type="password"]').first();
  if (!(await password.isVisible({ timeout: 2_000 }).catch(() => false))) {
    return;
  }
  await password.fill(WALLET_PASSWORD);
  await popup.getByRole("button", { name: /^Unlock$/ }).click();
  await Promise.race([
    popup
      .getByText(/^(Total\s+)?Balance$/i)
      .waitFor({ state: "visible", timeout: 30_000 }),
    popup
      .getByRole("button", {
        name: /^(Connect|Confirm|Approve|Allow|Deploy|Create)/,
      })
      .first()
      .waitFor({ state: "visible", timeout: 30_000 }),
  ]).catch(() => undefined);
}

/** Accept the next wallet approve popup (Connect / Deploy / Confirm). */
export async function acceptApproval(
  env: IdeWalletEnv,
  label: RegExp,
  opts?: { timeoutMs?: number },
): Promise<void> {
  const popup = await env.context.waitForEvent("page", {
    timeout: opts?.timeoutMs ?? 90_000,
  });
  try {
    await popup.waitForLoadState("domcontentloaded");
    await unlockIfNeeded(popup);
    let confirmLabel = label;
    const primary = popup.getByRole("button", { name: label }).first();
    if (!(await primary.isVisible({ timeout: 5_000 }).catch(() => false))) {
      confirmLabel = /^(Connect|Deploy|Confirm(?:\s+\d+)?|Approve|Allow)$/;
    }
    await clickConfirmation(popup, confirmLabel, 60_000);
    const { promise, resolve } = Promise.withResolvers<void>();
    popup.once("close", () => resolve());
    await Promise.race([promise, sleep(45_000)]);
  } finally {
    await popup.close().catch(() => undefined);
  }
}

export async function shot(page: Page, name: string): Promise<void> {
  fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  await page.screenshot({
    path: path.join(ARTIFACTS_DIR, `${name}.png`),
    fullPage: false,
  });
}

type UserTxItem = {
  tx_type: string | null;
  contract_id: unknown;
  eventMs: number | null;
};

function extractUserTxItems(body: unknown): UserTxItem[] {
  if (!body || typeof body !== "object") return [];
  if (!("data" in body)) return [];
  const data = body.data;
  if (!data || typeof data !== "object") return [];
  if (!("items" in data) || !Array.isArray(data.items)) return [];
  const out: UserTxItem[] = [];
  for (const raw of data.items) {
    if (!raw || typeof raw !== "object") continue;
    const txType =
      "tx_type" in raw && typeof raw.tx_type === "string" ? raw.tx_type : null;
    let contractId: unknown = null;
    if ("result" in raw && raw.result && typeof raw.result === "object") {
      if ("contract_id" in raw.result) contractId = raw.result.contract_id;
    }
    const tsCandidates = [
      "included_at" in raw && typeof raw.included_at === "string"
        ? raw.included_at
        : null,
      "received_at" in raw && typeof raw.received_at === "string"
        ? raw.received_at
        : null,
      "timestamp" in raw && typeof raw.timestamp === "string"
        ? raw.timestamp
        : null,
    ];
    let eventMs: number | null = null;
    for (const ts of tsCandidates) {
      if (!ts) continue;
      const n = Date.parse(ts);
      if (Number.isFinite(n)) {
        eventMs = n;
        break;
      }
    }
    out.push({ tx_type: txType, contract_id: contractId, eventMs });
  }
  return out;
}

function parseContractId(raw: unknown): number | null {
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;
  if (typeof raw === "string" && /^\d+$/.test(raw)) return Number(raw);
  return null;
}

/** Poll services for a recently deployed contract by user history. */
export async function waitForUserDeployContractId(
  userId: number,
  startedAtMs: number,
  minContractIdExclusive: number | null = null,
  timeoutMs = 10 * 60_000,
): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  let lastError = "";
  while (Date.now() < deadline) {
    try {
      const url = new URL("/api/v1/get/user/transactions", SERVICES_URL);
      url.searchParams.set("user_id", String(userId));
      url.searchParams.set("limit", "20");
      url.searchParams.set("offset", "0");
      const resp = await fetch(url);
      if (resp.ok) {
        const body: unknown = await resp.json();
        const items = extractUserTxItems(body);
        const windowStart = startedAtMs - 10 * 60_000;
        for (const item of items) {
          if (item.tx_type !== "deploy_contract") continue;
          const cid = parseContractId(item.contract_id);
          if (cid == null) continue;
          if (
            minContractIdExclusive != null &&
            cid <= minContractIdExclusive
          ) {
            continue;
          }
          if (item.eventMs != null && item.eventMs < windowStart) continue;
          return cid;
        }
      } else {
        lastError = `HTTP ${resp.status}`;
      }
    } catch (e: unknown) {
      lastError = e instanceof Error ? e.message : String(e);
    }
    await sleep(3_000);
  }
  throw new Error(
    `Timed out waiting for deploy_contract for user ${userId}` +
      (lastError ? ` (${lastError})` : ""),
  );
}

export const VOTING_CONTRACT_SOURCE = path.resolve(
  __dirname,
  "..",
  "fixtures",
  "VotingContract.psy.rs",
);

export interface CliDeployResult {
  /** Content-hash / contract uuid returned by the CLI. */
  contentHash: string;
  methods: number | null;
  stateTreeHeight: number | null;
  stdout: string;
}

/**
 * Compile + deploy a contract on-chain via psy_user_cli compile-and-deploy.
 *
 * Studio Deploy is gated on runtime-generated circuit definitions that the
 * browser compile path does not materialize. The CLI is the authoritative
 * on-chain deploy path for specialized e2e.
 */
export async function deployContractViaCli(opts?: {
  sourcePath?: string;
  privateKey?: string;
  outputDir?: string;
}): Promise<CliDeployResult> {
  assertCli();
  const sourcePath = opts?.sourcePath ?? VOTING_CONTRACT_SOURCE;
  const privateKey = (opts?.privateKey ?? SENDER_PK).replace(/^0x/, "");
  const outputDir =
    opts?.outputDir ?? path.join(ARTIFACTS_DIR, `deploy-${Date.now()}`);
  fs.mkdirSync(outputDir, { recursive: true });
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`deploy source missing: ${sourcePath}`);
  }

  const args = [
    "compile-and-deploy",
    "--source",
    sourcePath,
    "--private-key",
    privateKey,
    "--rpc-config",
    RPC_CONFIG,
    "--sign-type",
    "zk",
    "--output-dir",
    outputDir,
  ];

  let stdout = "";
  let stderr = "";
  try {
    const out = await execFileAsync(CLI_PATH, args, {
      timeout: 300_000,
      maxBuffer: 8 * 1024 * 1024,
      encoding: "utf8",
    });
    stdout = out.stdout;
    stderr = out.stderr;
  } catch (err: unknown) {
    const parts = execErrorParts(err);
    throw new Error(
      `compile-and-deploy failed: ${parts.message}\n${parts.stdout}\n${parts.stderr}`,
    );
  }

  const combined = `${stdout}\n${stderr}`;
  const hashMatch =
    combined.match(/Contract ID:\s*([0-9a-fA-F]{64})/) ??
    combined.match(/content_hash[=:\s]+([0-9a-fA-F]{64})/i) ??
    combined.match(/contract deployed:\s*([0-9a-fA-F]{64})/i);
  if (!hashMatch?.[1]) {
    throw new Error(
      `compile-and-deploy: no content hash in output:\n${combined.slice(0, 1200)}`,
    );
  }
  const methodsMatch = combined.match(/Methods:\s*(\d+)/i);
  const heightMatch = combined.match(/State tree height:\s*(\d+)/i);
  return {
    contentHash: hashMatch[1].toLowerCase(),
    methods: methodsMatch ? Number(methodsMatch[1]) : null,
    stateTreeHeight: heightMatch ? Number(heightMatch[1]) : null,
    stdout: combined,
  };
}

/** Resolve numeric contract id from services after a content-hash deploy. */
export async function waitForContractByContentHash(
  contentHash: string,
  timeoutMs = 5 * 60_000,
): Promise<{ contractId: number | null; uuid: string }> {
  const normalized = contentHash.replace(/^0x/, "").toLowerCase();
  const deadline = Date.now() + timeoutMs;
  let lastError = "";
  while (Date.now() < deadline) {
    try {
      // Prefer transaction-by-hash (includes result.contract_id when indexed).
      const txUrl = new URL(
        `/api/v1/transaction/hash/${normalized}`,
        SERVICES_URL,
      );
      const txResp = await fetch(txUrl);
      if (txResp.ok) {
        const body: unknown = await txResp.json();
        const cid = extractContractIdFromTxBody(body);
        if (cid != null) return { contractId: cid, uuid: normalized };
      }

      // Fallback: contracts list / by uuid.
      const byUuid = new URL(
        `/api/v1/contract/uuid/${normalized}`,
        SERVICES_URL,
      );
      const uuidResp = await fetch(byUuid);
      if (uuidResp.ok) {
        const body: unknown = await uuidResp.json();
        const cid = extractContractIdFromContractBody(body);
        if (cid != null) return { contractId: cid, uuid: normalized };
        // Even without numeric id, uuid is known.
        return { contractId: null, uuid: normalized };
      }

      lastError = `tx=${txResp.status} uuid=${uuidResp.status}`;
    } catch (e: unknown) {
      lastError = e instanceof Error ? e.message : String(e);
    }
    await sleep(2_000);
  }
  // Deploy was accepted by coordinator even if indexer lags — return uuid.
  console.warn(
    `[ide-deploy] indexer lag for ${normalized}: ${lastError}; returning uuid only`,
  );
  return { contractId: null, uuid: normalized };
}

function extractContractIdFromTxBody(body: unknown): number | null {
  if (!body || typeof body !== "object") return null;
  if (!("data" in body) || !body.data || typeof body.data !== "object") {
    return null;
  }
  const data = body.data;
  if ("result" in data && data.result && typeof data.result === "object") {
    if ("contract_id" in data.result) {
      return parseContractId(data.result.contract_id);
    }
  }
  if ("contract_id" in data) return parseContractId(data.contract_id);
  return null;
}

function extractContractIdFromContractBody(body: unknown): number | null {
  if (!body || typeof body !== "object") return null;
  if (!("data" in body) || !body.data || typeof body.data !== "object") {
    return null;
  }
  const data = body.data;
  if ("contract_id" in data) return parseContractId(data.contract_id);
  if ("id" in data) return parseContractId(data.id);
  return null;
}
