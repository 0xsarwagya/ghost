import { defineConfig, devices } from "@playwright/test";

/**
 * Cross-browser matrix for ghost.
 *
 *  chromium-identity    : persistence lab. Create identity, reload the page,
 *                         prove the same non-extractable key survives
 *                         IndexedDB, sign a challenge, verify the proof in
 *                         Node with the real server verifier, then reset.
 *  firefox-identity     : same journey on Gecko.
 *  webkit-identity      : same journey on WebKit.
 *  chromium-protocol    : protocol test vectors recomputed in-engine, plus
 *                         adversarial mutations verified against src/server.
 *  firefox-protocol     : same on Gecko.
 *  webkit-protocol      : same on WebKit.
 *  chromium-unsupported : crypto.subtle stubbed out; the library must surface
 *                         UNSUPPORTED cleanly. Chromium-only because the code
 *                         path is engine-independent.
 *
 * The identity projects are the release gate: the protocol does not freeze
 * until all three engines persist a non-extractable key across a reload.
 */
export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "on-first-retry",
  },
  webServer: {
    command:
      "pnpm exec vite --config tests/e2e/fixtures/vite.config.ts --port 4173 --strictPort",
    url: "http://127.0.0.1:4173/identity.html",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
  projects: [
    {
      name: "chromium-identity",
      testMatch: /identity\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox-identity",
      testMatch: /identity\.spec\.ts$/,
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit-identity",
      testMatch: /identity\.spec\.ts$/,
      use: { ...devices["Desktop Safari"] },
    },
    {
      name: "chromium-protocol",
      testMatch: /protocol\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox-protocol",
      testMatch: /protocol\.spec\.ts$/,
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit-protocol",
      testMatch: /protocol\.spec\.ts$/,
      use: { ...devices["Desktop Safari"] },
    },
    {
      name: "chromium-unsupported",
      testMatch: /unsupported\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
