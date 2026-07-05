import { expect, test, type Page } from "@playwright/test";

import { GHOST_ID_PATTERN } from "../../src/protocol/constants.js";
import { createChallenge } from "../../src/server/challenge.js";
import {
  InMemoryChallengeStore,
  InMemoryGhostCredentialStore,
} from "../../src/server/store.js";
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
    __create: () => Promise<{ id: string; credentialId: string; publicKey: string }>;
    __enableRecovery: () => Promise<{
      recoverySecret: string;
      recoveryRecord: {
        version: 1;
        method: "recovery-secret";
        ghostId: string;
        authorityId: string;
        createdAt: number;
      };
    }>;
    __recover: (
      recoverySecret: string,
      recoveryRecord: Awaited<ReturnType<Window["__enableRecovery"]>>["recoveryRecord"],
    ) => Promise<{ id: string; credentialId: string; publicKey: string }>;
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
    expect(second.credentialId).toBe(first.credentialId);
    expect(second.publicKey).toBe(first.publicKey);

    // Browser signs, Node verifies — the real trust boundary.
    const store = new InMemoryChallengeStore();
    const credentials = new InMemoryGhostCredentialStore();
    credentials.register(first);
    const challenge = createChallenge({ audience: AUDIENCE, action: "login" });
    const proof = await page.evaluate(
      (c) => window.__sign(c),
      challenge as unknown,
    );
    const result = await verifyGhostProof(proof, {
      expectedAudience: AUDIENCE,
      expectedAction: "login",
      challengeStore: store,
      credentialStore: credentials,
    });
    expect(result).toEqual({
      ok: true,
      ghostId: first.id,
      credentialId: first.credentialId,
      publicKey: first.publicKey,
      action: "login",
    });

    // The same proof must not verify twice.
    const replay = await verifyGhostProof(proof, {
      expectedAudience: AUDIENCE,
      challengeStore: store,
      credentialStore: credentials,
    });
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(replay.code).toBe("CHALLENGE_REUSED");
    }
  });

  test("identity-bound challenges only sign for their ghost", async ({ page }) => {
    await open(page);
    const ghost = await page.evaluate(() => window.__create());

    const foreign = createChallenge({
      audience: AUDIENCE,
      action: "login",
      ghostId: `ghost_1_${"a".repeat(32)}`,
    });
    expect(await page.evaluate((c) => window.__signError(c), foreign as unknown)).toBe(
      "INVALID_CHALLENGE",
    );

    const own = createChallenge({ audience: AUDIENCE, action: "login", ghostId: ghost.id });
    const proof = await page.evaluate((c) => window.__sign(c), own as unknown);
    const credentials = new InMemoryGhostCredentialStore();
    credentials.register(ghost);
    const result = await verifyGhostProof(proof, {
      expectedAudience: AUDIENCE,
      expectedGhostId: ghost.id,
      challengeStore: new InMemoryChallengeStore(),
      credentialStore: credentials,
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

  test("recovery keeps the ghost ID while rotating the credential", async ({
    page,
  }) => {
    await open(page);
    const before = await page.evaluate(() => window.__create());
    const recovery = await page.evaluate(() => window.__enableRecovery());

    await page.evaluate(
      () =>
        new Promise<void>((resolve, reject) => {
          const request = indexedDB.deleteDatabase("ghost");
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error);
          request.onblocked = () => reject(new Error("deleteDatabase blocked"));
        }),
    );
    await page.reload();
    await page.waitForFunction(() => window.__ready === true);

    const recovered = await page.evaluate(
      ({ recoverySecret, recoveryRecord }) =>
        window.__recover(recoverySecret, recoveryRecord),
      recovery,
    );
    expect(recovered.id).toBe(before.id);
    expect(recovered.credentialId).not.toBe(before.credentialId);
    expect(recovered.publicKey).not.toBe(before.publicKey);

    const credentials = new InMemoryGhostCredentialStore();
    credentials.register(recovered);
    const challenge = createChallenge({
      audience: AUDIENCE,
      action: "login",
      ghostId: recovered.id,
    });
    const proof = await page.evaluate((c) => window.__sign(c), challenge as unknown);
    const result = await verifyGhostProof(proof, {
      expectedAudience: AUDIENCE,
      expectedGhostId: recovered.id,
      challengeStore: new InMemoryChallengeStore(),
      credentialStore: credentials,
    });
    expect(result.ok).toBe(true);
  });
});
