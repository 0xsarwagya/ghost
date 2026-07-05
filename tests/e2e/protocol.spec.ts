import { expect, test, type Page } from "@playwright/test";

import { createChallenge } from "../../src/server/challenge.js";
import {
  InMemoryChallengeStore,
  InMemoryGhostCredentialStore,
} from "../../src/server/store.js";
import { verifyGhostProof } from "../../src/server/verify.js";
import type { GhostProof } from "../../src/protocol/proof.js";
import type { VectorReport } from "../protocol-vectors.js";

/**
 * Protocol conformance per engine: the pinned vectors must recompute
 * byte-for-byte in the browser, and proofs produced in the browser must
 * fail server verification in exactly the right way when tampered with.
 */

const AUDIENCE = "https://ghost.test";

declare global {
  interface Window {
    __ready?: boolean;
    __runVectors: () => Promise<VectorReport>;
    __create: () => Promise<{ id: string; credentialId: string; publicKey: string }>;
    __sign: (challenge: unknown) => Promise<unknown>;
  }
}

test("pinned protocol vectors recompute in-engine", async ({ page }) => {
  await page.goto("/protocol.html");
  await page.waitForFunction(() => window.__ready === true);
  const report = await page.evaluate(() => window.__runVectors());
  for (const check of report.checks) {
    expect(check.pass, `${check.name}${check.detail ? ` — ${check.detail}` : ""}`).toBe(
      true,
    );
  }
  expect(report.checks).toHaveLength(8);
});

test.describe("adversarial verification of browser-made proofs", () => {
  async function makeProof(
    page: Page,
  ): Promise<{ proof: GhostProof; credentials: InMemoryGhostCredentialStore }> {
    await page.goto("/identity.html");
    await page.waitForFunction(() => window.__ready === true);
    const ghost = await page.evaluate(() => window.__create());
    const credentials = new InMemoryGhostCredentialStore();
    credentials.register(ghost);
    const challenge = createChallenge({ audience: AUDIENCE, action: "login" });
    const proof = (await page.evaluate(
      (c) => window.__sign(c),
      challenge as unknown,
    )) as GhostProof;
    return { proof, credentials };
  }

  async function expectCode(
    proof: unknown,
    code: string,
    credentials: InMemoryGhostCredentialStore,
    expectedAudience = AUDIENCE,
  ) {
    const result = await verifyGhostProof(proof, {
      expectedAudience,
      challengeStore: new InMemoryChallengeStore(),
      credentialStore: credentials,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe(code);
    }
  }

  test("the untampered proof verifies, each mutation fails typed", async ({ page }) => {
    const { proof, credentials } = await makeProof(page);

    const pristine = await verifyGhostProof(proof, {
      expectedAudience: AUDIENCE,
      challengeStore: new InMemoryChallengeStore(),
      credentialStore: credentials,
    });
    expect(pristine.ok).toBe(true);

    // Flip one signature character.
    const flipped =
      proof.signature[0] === "A" ? `B${proof.signature.slice(1)}` : `A${proof.signature.slice(1)}`;
    await expectCode({ ...proof, signature: flipped }, "INVALID_SIGNATURE", credentials);

    // Rewrite the signed audience — signature no longer covers it.
    await expectCode(
      { ...proof, challenge: { ...proof.challenge, audience: "https://evil.test" } },
      "INVALID_SIGNATURE",
      credentials,
      "https://evil.test",
    );

    // Same proof presented to a different audience.
    await expectCode(proof, "AUDIENCE_MISMATCH", credentials, "https://other.test");

    // Claim a different identity over the same key.
    await expectCode(
      { ...proof, ghostId: `ghost_1_${"a".repeat(32)}` },
      "INVALID_SIGNATURE",
      credentials,
    );

    // Future protocol version.
    await expectCode({ ...proof, version: 2 }, "UNSUPPORTED_VERSION", credentials);
  });

  test("an expired browser proof is rejected", async ({ page }) => {
    await page.goto("/identity.html");
    await page.waitForFunction(() => window.__ready === true);
    const ghost = await page.evaluate(() => window.__create());
    const credentials = new InMemoryGhostCredentialStore();
    credentials.register(ghost);
    const challenge = createChallenge({ audience: AUDIENCE, action: "login", ttlMs: 60_000 });
    const proof = await page.evaluate((c) => window.__sign(c), challenge as unknown);
    const result = await verifyGhostProof(proof, {
      expectedAudience: AUDIENCE,
      challengeStore: new InMemoryChallengeStore(),
      credentialStore: credentials,
      now: () => challenge.expiresAt + 1,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("CHALLENGE_EXPIRED");
    }
  });
});
