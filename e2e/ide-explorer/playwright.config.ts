import { defineConfig } from "@playwright/test";

/**
 * Specialized IDE + Explorer E2E against a running local stack.
 *
 * Prerequisites (make run-all or equivalent):
 *   - IDE        http://127.0.0.1:5176
 *   - Explorer   http://127.0.0.1:5178
 *   - psy-services / indexer / coordinator healthy
 *   - For IDE-05 deploy: built psy-wallet dist + target/release/psy_user_cli
 *
 * Override with IDE_URL / EXPLORER_URL / PSY_WALLET_DIST / SERVICES_URL.
 */
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 20_000 },
  reporter: [["list"]],
  outputDir: "test-results",
  use: {
    headless: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    actionTimeout: 20_000,
    navigationTimeout: 30_000,
  },
  projects: [
    {
      name: "ide",
      testMatch: /ide\.spec\.ts/,
      use: {
        baseURL: process.env.IDE_URL ?? "http://127.0.0.1:5176",
      },
    },
    {
      name: "ide-deploy",
      testMatch: /ide-deploy\.spec\.ts/,
      timeout: 15 * 60_000,
      expect: { timeout: 60_000 },
      use: {
        baseURL: process.env.IDE_URL ?? "http://127.0.0.1:5176",
        actionTimeout: 60_000,
        navigationTimeout: 60_000,
      },
    },
    {
      name: "explorer",
      testMatch: /explorer\.spec\.ts/,
      use: {
        baseURL: process.env.EXPLORER_URL ?? "http://127.0.0.1:5178",
      },
    },
  ],
});
