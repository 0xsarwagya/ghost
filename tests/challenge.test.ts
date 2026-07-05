import { describe, expect, it } from "vitest";

import { isGhostError } from "../src/errors.js";
import {
  assertChallengeShape,
  canonicalChallengeBytes,
  type GhostChallenge,
} from "../src/protocol/challenge.js";

const VALID: GhostChallenge = {
  version: 1,
  nonce: "dGVzdC1ub25jZQ",
  audience: "https://ghost.test",
  action: "login",
  expiresAt: 4102444800000,
};

function expectCode(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (error) {
    expect(isGhostError(error)).toBe(true);
    if (isGhostError(error)) {
      expect(error.code).toBe(code);
    }
    return;
  }
  expect.fail("expected a GhostError");
}

describe("canonicalChallengeBytes", () => {
  it("is independent of object key insertion order", () => {
    const reordered = JSON.parse(
      '{"expiresAt":4102444800000,"action":"login","audience":"https://ghost.test","nonce":"dGVzdC1ub25jZQ","version":1}',
    ) as GhostChallenge;
    expect(canonicalChallengeBytes(reordered)).toEqual(
      canonicalChallengeBytes(VALID),
    );
  });

  it("changes when any field changes", () => {
    const base = canonicalChallengeBytes(VALID);
    const variants: GhostChallenge[] = [
      { ...VALID, nonce: "dGVzdC1ub25jZX" },
      { ...VALID, audience: "https://ghost.test2" },
      { ...VALID, action: "delete" },
      { ...VALID, expiresAt: 4102444800001 },
      { ...VALID, ghostId: `ghost_1_${"a".repeat(32)}` },
    ];
    for (const variant of variants) {
      expect(canonicalChallengeBytes(variant)).not.toEqual(base);
    }
  });

  it("cannot smuggle bytes across field boundaries", () => {
    // Moving a suffix of one field to the prefix of the next must change
    // the canonical bytes despite identical concatenated content.
    const a = canonicalChallengeBytes({ ...VALID, audience: "ab", action: "clogin" });
    const b = canonicalChallengeBytes({ ...VALID, audience: "abc", action: "login" });
    expect(a).not.toEqual(b);
  });
});

describe("assertChallengeShape", () => {
  it("accepts a valid challenge, with or without ghostId", () => {
    expect(() => assertChallengeShape(VALID, "sign")).not.toThrow();
    expect(() =>
      assertChallengeShape(
        { ...VALID, ghostId: `ghost_1_${"b".repeat(32)}` },
        "sign",
      ),
    ).not.toThrow();
  });

  it("rejects wrong versions with UNSUPPORTED_VERSION", () => {
    expectCode(
      () => assertChallengeShape({ ...VALID, version: 2 }, "sign"),
      "UNSUPPORTED_VERSION",
    );
  });

  it("rejects structural problems with INVALID_CHALLENGE", () => {
    const bad: unknown[] = [
      null,
      "challenge",
      { ...VALID, version: "1" },
      { ...VALID, nonce: "" },
      { ...VALID, audience: 42 },
      { ...VALID, action: undefined },
      { ...VALID, expiresAt: "4102444800000" },
      { ...VALID, expiresAt: 1.5 },
      { ...VALID, expiresAt: -1 },
      { ...VALID, ghostId: "" },
      { ...VALID, ghostId: "ghost_1_short" },
    ];
    for (const value of bad) {
      expectCode(() => assertChallengeShape(value, "sign"), "INVALID_CHALLENGE");
    }
  });
});
