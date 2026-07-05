import { describe, expect, it } from "vitest";

import {
  decodeBase64Url,
  encodeBase32,
  encodeBase64Url,
  lengthPrefixedConcat,
  utf8Bytes,
} from "../src/protocol/encoding.js";

// RFC 4648 §10 vectors, lowercased with padding stripped.
const BASE32_VECTORS: Array<[string, string]> = [
  ["", ""],
  ["f", "my"],
  ["fo", "mzxq"],
  ["foo", "mzxw6"],
  ["foob", "mzxw6yq"],
  ["fooba", "mzxw6ytb"],
  ["foobar", "mzxw6ytboi"],
];

describe("encodeBase32", () => {
  it("matches the RFC 4648 test vectors", () => {
    for (const [input, expected] of BASE32_VECTORS) {
      expect(encodeBase32(utf8Bytes(input))).toBe(expected);
    }
  });

  it("encodes 20 bytes to exactly 32 characters", () => {
    const bytes = new Uint8Array(20).fill(0xff);
    expect(encodeBase32(bytes)).toHaveLength(32);
    expect(encodeBase32(new Uint8Array(20))).toBe("a".repeat(32));
  });
});

describe("base64url", () => {
  it("round-trips every byte value", () => {
    const bytes = new Uint8Array(256);
    for (let i = 0; i < 256; i += 1) {
      bytes[i] = i;
    }
    expect(decodeBase64Url(encodeBase64Url(bytes))).toEqual(bytes);
  });

  it("round-trips lengths that hit each remainder branch", () => {
    for (const length of [0, 1, 2, 3, 4, 31, 32, 33, 64]) {
      const bytes = new Uint8Array(length).map((_, i) => (i * 37 + 11) % 256);
      const encoded = encodeBase64Url(bytes);
      expect(encoded).not.toMatch(/[+/=]/);
      expect(decodeBase64Url(encoded)).toEqual(bytes);
    }
  });

  it("rejects standard-base64 and malformed input", () => {
    expect(() => decodeBase64Url("ab+c")).toThrow(SyntaxError);
    expect(() => decodeBase64Url("ab/c")).toThrow(SyntaxError);
    expect(() => decodeBase64Url("abc=")).toThrow(SyntaxError);
    expect(() => decodeBase64Url("a")).toThrow(SyntaxError);
    expect(() => decodeBase64Url("a b")).toThrow(SyntaxError);
  });
});

describe("lengthPrefixedConcat", () => {
  it("prefixes each field with its uint32 big-endian length", () => {
    const output = lengthPrefixedConcat([utf8Bytes("ab"), utf8Bytes("c")]);
    expect(Array.from(output)).toEqual([
      0, 0, 0, 2, 0x61, 0x62,
      0, 0, 0, 1, 0x63,
    ]);
  });

  it("keeps empty fields distinguishable from absent ones", () => {
    const withEmpty = lengthPrefixedConcat([utf8Bytes("a"), utf8Bytes("")]);
    const without = lengthPrefixedConcat([utf8Bytes("a")]);
    expect(withEmpty).not.toEqual(without);
    expect(Array.from(withEmpty)).toEqual([0, 0, 0, 1, 0x61, 0, 0, 0, 0]);
  });

  it("cannot be confused by field content that looks like a prefix", () => {
    // ["ab","c"] vs ["ab\x00\x00\x00\x01c"] must differ.
    const split = lengthPrefixedConcat([utf8Bytes("ab"), utf8Bytes("c")]);
    const merged = lengthPrefixedConcat([
      new Uint8Array([0x61, 0x62, 0, 0, 0, 1, 0x63]),
    ]);
    expect(split).not.toEqual(merged);
  });
});
