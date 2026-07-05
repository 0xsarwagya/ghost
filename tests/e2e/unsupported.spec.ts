import { expect, test } from "@playwright/test";

/**
 * Ghost must surface broken runtimes as typed errors, not mystery
 * rejections. Chromium-only: the code paths are engine-independent.
 */

declare global {
  interface Window {
    __done?: boolean;
    __result: { supported: boolean | null; code: string | null };
  }
}

test("a runtime without Web Crypto surfaces UNSUPPORTED", async ({ page }) => {
  await page.goto("/unsupported.html?mode=nocrypto");
  await page.waitForFunction(() => window.__done === true);
  const result = await page.evaluate(() => window.__result);
  expect(result.supported).toBe(false);
  expect(result.code).toBe("UNSUPPORTED");
});

test("failing key generation surfaces KEY_GENERATION_FAILED", async ({ page }) => {
  await page.goto("/unsupported.html?mode=keygen");
  await page.waitForFunction(() => window.__done === true);
  const result = await page.evaluate(() => window.__result);
  expect(result.supported).toBe(false);
  expect(result.code).toBe("KEY_GENERATION_FAILED");
});
