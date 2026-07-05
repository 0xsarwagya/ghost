import { expect, test, type Page } from "@playwright/test";

import { GHOST_ID_PATTERN } from "../../src/protocol/constants.js";
import { createChallenge } from "../../src/server/challenge.js";
import { InMemoryChallengeStore } from "../../src/server/store.js";
import { verifyGhostProof } from "../../src/server/verify.js";

/**
 * The persistence lab — the release gate for protocol v1.
 *
 * A non-extractable Ed25519 CryptoKey must survive IndexedDB structured
 * clone across a page reload in every engine, and a proof signed in the
 * browser must verify with the real server verifier running here in Node.
 * If any engine fails this spec, the protocol does not freeze.
 */

const AUDIENCE = "https://ghost.test";

declare global {
  interface Window {
    __ready?: boolean;
    __capabilities: () => Promise<{ supported: boolean }>;
    __create: () => Promise<{ id: string; publicKey: string }>;
    __sign: (challenge: unknown) => Promise<unknown>;
    __signError: (challenge: unknown) => Promise<string | null>;
    __reset: () => Promise<boolean>;
  }
}

async function open(page: Page): Promise<void> {
  await page.goto("/identity.html");
  await page.waitForFunction(() => window.__ready === true, undefined, {
    timeout: 10_000,
  });
}

test.describe("ghost identity persistence", () => {
  test("capabilities report full support", async ({ page }) => {
    await open(page);
    const caps = await page.evaluate(() => window.__capabilities());
    expect(caps.supported).toBe(true);
  });

  test("identity survives a reload and proofs verify server-side", async ({
    page,
  }) => {
    await open(page);

    const first = await page.evaluate(() => window.__create());
    expect(first.id).toMatch(GHOST_ID_PATTERN);

    // The load-bearing moment: a fresh page must find the same
    // non-extractable key in IndexedDB and derive the same identity.
    await page.reload();
    await page.waitForFunction(() => window.__ready === true);
    const second = await page.evaluate(() => window.__create());
    expect(second.id).toBe(first.id);
    expect(second.publicKey).toBe(first.publicKey);

    // Browser signs, Node verifies — the real trust boundary.
    const store = new InMemoryChallengeStore();
    const challenge = createChallenge({ audience: AUDIENCE, action: "login" });
    const proof = await page.evaluate(
      (c) => window.__sign(c),
      challenge as unknown,
    );
    const result = await verifyGhostProof(proof, {
      expectedAudience: AUDIENCE,
      expectedAction: "login",
      challengeStore: store,
    });
    expect(result).toEqual({
      ok: true,
      ghostId: first.id,
      publicKey: first.publicKey,
      action: "login",
    });

    // The same proof must not verify twice.
    const replay = await verifyGhostProof(proof, {
      expectedAudience: AUDIENCE,
      challengeStore: store,
    });
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(replay.code).toBe("CHALLENGE_REUSED");
    }
  });

  test("identity-bound challenges only sign for their ghost", async ({ page }) => {
    await open(page);
    const { id } = await page.evaluate(() => window.__create());

    const foreign = createChallenge({
      audience: AUDIENCE,
      action: "login",
      ghostId: `ghost_1_${"a".repeat(32)}`,
    });
    expect(await page.evaluate((c) => window.__signError(c), foreign as unknown)).toBe(
      "INVALID_CHALLENGE",
    );

    const own = createChallenge({ audience: AUDIENCE, action: "login", ghostId: id });
    const proof = await page.evaluate((c) => window.__sign(c), own as unknown);
    const result = await verifyGhostProof(proof, {
      expectedAudience: AUDIENCE,
      expectedGhostId: id,
      challengeStore: new InMemoryChallengeStore(),
    });
    expect(result.ok).toBe(true);
  });

  test("expired challenges are refused locally", async ({ page }) => {
    await open(page);
    await page.evaluate(() => window.__create());
    const expired = createChallenge({
      audience: AUDIENCE,
      action: "login",
      ttlMs: 1,
      now: () => Date.now() - 60_000,
    });
    expect(await page.evaluate((c) => window.__signError(c), expired as unknown)).toBe(
      "CHALLENGE_EXPIRED",
    );
  });

  test("reset destroys the identity permanently", async ({ page }) => {
    await open(page);
    const before = await page.evaluate(() => window.__create());
    await page.evaluate(() => window.__reset());

    await page.reload();
    await page.waitForFunction(() => window.__ready === true);
    const after = await page.evaluate(() => window.__create());
    expect(after.id).toMatch(GHOST_ID_PATTERN);
    expect(after.id).not.toBe(before.id);
  });
});
