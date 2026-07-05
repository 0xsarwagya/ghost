import { describe, expect, it } from "vitest";

import { isGhostError } from "../src/errors.js";
import { encodeBase64Url } from "../src/protocol/encoding.js";
import type { GhostProof } from "../src/protocol/proof.js";
import { createChallenge } from "../src/server/challenge.js";
import { InMemoryChallengeStore } from "../src/server/store.js";
import { verifyGhostProof, type VerifyGhostProofOptions } from "../src/server/verify.js";
import {
  BOUND_CHALLENGE,
  BOUND_SIGNATURE_HEX,
  FIXTURE_GHOST_ID,
  FIXTURE_PUBLIC_KEY_BASE64URL,
  hexToBytes,
  UNBOUND_CHALLENGE,
  UNBOUND_SIGNATURE_HEX,
} from "./protocol-vectors.js";

const AUDIENCE = "https://ghost.test";

function validProof(): GhostProof {
  return {
    version: 1,
    algorithm: "ed25519",
    ghostId: FIXTURE_GHOST_ID,
    publicKey: FIXTURE_PUBLIC_KEY_BASE64URL,
    challenge: { ...UNBOUND_CHALLENGE },
    signature: encodeBase64Url(hexToBytes(UNBOUND_SIGNATURE_HEX)),
  };
}

function options(
  overrides: Partial<VerifyGhostProofOptions> = {},
): VerifyGhostProofOptions {
  return {
    expectedAudience: AUDIENCE,
    challengeStore: new InMemoryChallengeStore(),
    ...overrides,
  };
}

async function expectRejection(
  proof: unknown,
  code: string,
  overrides: Partial<VerifyGhostProofOptions> = {},
): Promise<void> {
  const result = await verifyGhostProof(proof, options(overrides));
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.code).toBe(code);
  }
}

describe("verifyGhostProof", () => {
  it("accepts a valid proof", async () => {
    const result = await verifyGhostProof(validProof(), options());
    expect(result).toEqual({
      ok: true,
      ghostId: FIXTURE_GHOST_ID,
      publicKey: FIXTURE_PUBLIC_KEY_BASE64URL,
      action: "login",
    });
  });

  it("accepts a proof for an identity-bound challenge", async () => {
    const proof = validProof();
    proof.challenge = { ...BOUND_CHALLENGE };
    proof.signature = encodeBase64Url(hexToBytes(BOUND_SIGNATURE_HEX));
    const result = await verifyGhostProof(
      proof,
      options({ expectedAction: "delete-note", expectedGhostId: FIXTURE_GHOST_ID }),
    );
    expect(result.ok).toBe(true);
  });

  it("rejects a replayed nonce with CHALLENGE_REUSED", async () => {
    const shared = options();
    expect((await verifyGhostProof(validProof(), shared)).ok).toBe(true);
    const replayed = await verifyGhostProof(validProof(), shared);
    expect(replayed.ok).toBe(false);
    if (!replayed.ok) {
      expect(replayed.code).toBe("CHALLENGE_REUSED");
    }
  });

  it("does not burn the nonce when verification fails", async () => {
    const shared = options();
    const tampered = validProof();
    tampered.challenge.action = "admin";
    const failed = await verifyGhostProof(tampered, shared);
    expect(failed.ok).toBe(false);
    expect((await verifyGhostProof(validProof(), shared)).ok).toBe(true);
  });

  it("rejects a tampered signature", async () => {
    const sig = hexToBytes(UNBOUND_SIGNATURE_HEX);
    const first = sig[0];
    if (first !== undefined) {
      sig[0] = first ^ 0xff;
    }
    const proof = validProof();
    proof.signature = encodeBase64Url(sig);
    await expectRejection(proof, "INVALID_SIGNATURE");
  });

  it("rejects a tampered challenge field", async () => {
    const proof = validProof();
    proof.challenge.nonce = `${proof.challenge.nonce.slice(0, -1)}X`;
    await expectRejection(proof, "INVALID_SIGNATURE");
  });

  it("rejects an expired challenge", async () => {
    await expectRejection(validProof(), "CHALLENGE_EXPIRED", {
      now: () => UNBOUND_CHALLENGE.expiresAt + 1,
    });
  });

  it("rejects a foreign audience", async () => {
    await expectRejection(validProof(), "AUDIENCE_MISMATCH", {
      expectedAudience: "https://other.test",
    });
  });

  it("rejects an unexpected action", async () => {
    await expectRejection(validProof(), "INVALID_CHALLENGE", {
      expectedAction: "delete-note",
    });
  });

  it("rejects an unexpected identity", async () => {
    await expectRejection(validProof(), "INVALID_CHALLENGE", {
      expectedGhostId: `ghost_1_${"a".repeat(32)}`,
    });
  });

  it("rejects a challenge bound to a different identity", async () => {
    const proof = validProof();
    proof.challenge.ghostId = `ghost_1_${"a".repeat(32)}`;
    await expectRejection(proof, "INVALID_CHALLENGE");
  });

  it("rejects a ghost ID that does not match the public key", async () => {
    const proof = validProof();
    proof.ghostId = `ghost_1_${"a".repeat(32)}`;
    await expectRejection(proof, "INVALID_SIGNATURE");
  });

  it("rejects unsupported versions and algorithms", async () => {
    const wrongVersion = { ...validProof(), version: 2 };
    await expectRejection(wrongVersion, "UNSUPPORTED_VERSION");
    const wrongAlgorithm = { ...validProof(), algorithm: "p256" };
    await expectRejection(wrongAlgorithm, "UNSUPPORTED_VERSION");
  });

  it("rejects malformed proofs without throwing", async () => {
    for (const proof of [null, "proof", {}, { version: 1 }]) {
      await expectRejection(proof, "INVALID_CHALLENGE");
    }
  });

  it("rejects undecodable or wrong-length key material", async () => {
    const badKey = { ...validProof(), publicKey: "not base64url!!" };
    await expectRejection(badKey, "INVALID_SIGNATURE");
    const shortKey = { ...validProof(), publicKey: encodeBase64Url(new Uint8Array(16)) };
    await expectRejection(shortKey, "INVALID_SIGNATURE");
    const shortSig = { ...validProof(), signature: encodeBase64Url(new Uint8Array(10)) };
    await expectRejection(shortSig, "INVALID_SIGNATURE");
  });

  it("throws GhostError on caller misconfiguration", async () => {
    await expect(
      verifyGhostProof(validProof(), {} as VerifyGhostProofOptions),
    ).rejects.toSatisfy(isGhostError);
    await expect(
      verifyGhostProof(validProof(), {
        expectedAudience: AUDIENCE,
      } as VerifyGhostProofOptions),
    ).rejects.toSatisfy(isGhostError);
  });
});

describe("createChallenge", () => {
  it("creates a well-formed challenge with fresh nonces", () => {
    const first = createChallenge({ audience: AUDIENCE, action: "login" });
    const second = createChallenge({ audience: AUDIENCE, action: "login" });
    expect(first.version).toBe(1);
    expect(first.audience).toBe(AUDIENCE);
    expect(first.action).toBe("login");
    expect(first.nonce).toHaveLength(43); // 32 bytes of base64url
    expect(first.nonce).not.toBe(second.nonce);
    expect(first.ghostId).toBeUndefined();
  });

  it("applies ttl relative to the injected clock", () => {
    const challenge = createChallenge({
      audience: AUDIENCE,
      action: "login",
      ttlMs: 5_000,
      now: () => 1_000_000,
    });
    expect(challenge.expiresAt).toBe(1_005_000);
  });

  it("binds to an identity when asked", () => {
    const challenge = createChallenge({
      audience: AUDIENCE,
      action: "login",
      ghostId: FIXTURE_GHOST_ID,
    });
    expect(challenge.ghostId).toBe(FIXTURE_GHOST_ID);
  });

  it("rejects bad input with GhostError", () => {
    const bad = [
      { audience: "", action: "login" },
      { audience: AUDIENCE, action: "" },
      { audience: AUDIENCE, action: "login", ghostId: "ghost_1_nope" },
      { audience: AUDIENCE, action: "login", ttlMs: 0 },
      { audience: AUDIENCE, action: "login", ttlMs: 1.5 },
    ];
    for (const input of bad) {
      expect(() => createChallenge(input)).toThrow(expect.toSatisfy(isGhostError));
    }
  });
});

describe("InMemoryChallengeStore", () => {
  it("consumes a nonce exactly once under concurrency", async () => {
    const store = new InMemoryChallengeStore();
    const results = await Promise.all(
      Array.from({ length: 50 }, () => store.consume("nonce", Date.now() + 60_000)),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("sweeps expired entries", async () => {
    let now = 1_000;
    const store = new InMemoryChallengeStore({ now: () => now });
    await store.consume("a", 2_000);
    await store.consume("b", 5_000);
    expect(store.size).toBe(2);
    now = 3_000;
    await store.consume("c", 5_000);
    expect(store.size).toBe(2); // "a" swept, "b" and "c" remain
    // A swept nonce could in principle be consumed again — that is fine,
    // because expired challenges never reach the store.
  });
});
