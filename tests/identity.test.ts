import { describe, expect, it } from "vitest";

import { GHOST_ID_PATTERN } from "../src/protocol/constants.js";
import { deriveGhostId, isGhostId, parseGhostId } from "../src/protocol/identity.js";

describe("deriveGhostId", () => {
  it("is deterministic and matches the v1 grammar", async () => {
    const key = new Uint8Array(32).map((_, i) => i);
    const first = await deriveGhostId(key);
    const second = await deriveGhostId(key);
    expect(first).toBe(second);
    expect(first).toMatch(GHOST_ID_PATTERN);
    expect(first).toHaveLength(40);
  });

  it("produces different ids for different keys", async () => {
    const a = await deriveGhostId(new Uint8Array(32).fill(1));
    const b = await deriveGhostId(new Uint8Array(32).fill(2));
    expect(a).not.toBe(b);
  });
});

describe("isGhostId / parseGhostId", () => {
  it("accepts a derived id", async () => {
    const id = await deriveGhostId(new Uint8Array(32).fill(7));
    expect(isGhostId(id)).toBe(true);
    expect(parseGhostId(id)).toEqual({ version: 1 });
  });

  it("rejects malformed identifiers", () => {
    for (const value of [
      "",
      "ghost_1_",
      "ghost_1_TOOSHORT",
      `ghost_1_${"a".repeat(31)}`,
      `ghost_1_${"a".repeat(33)}`,
      `ghost_1_${"a".repeat(31)}1`, // "1" is outside the base32 alphabet
      `ghost_1_${"A".repeat(32)}`, // uppercase is not canonical
      `ghost_0_${"a".repeat(32)}`,
      `ghost_${"a".repeat(32)}`,
      `spooky_1_${"a".repeat(32)}`,
    ]) {
      expect(isGhostId(value)).toBe(false);
      expect(parseGhostId(value)).toBeNull();
    }
  });

  it("reports future versions without validating their grammar", () => {
    expect(parseGhostId("ghost_2_abc234")).toEqual({ version: 2 });
    expect(isGhostId("ghost_2_abc234")).toBe(false);
  });
});
