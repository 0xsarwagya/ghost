/**
 * Deterministic protocol v1 test vectors.
 *
 * The fixture keypair is RFC 8032 §7.1 TEST 1 (the private key is that
 * seed wrapped in the constant PKCS#8 prefix, because Web Crypto imports
 * Ed25519 private keys only as PKCS#8). Everything below was generated
 * once from the real implementation, cross-checked against the RFC's
 * public key and empty-message signature, and is now pinned: any drift in
 * encoding, identity derivation, or signing is a protocol break, not a
 * refactor.
 *
 * This module must stay runnable in both Node (vitest) and browsers
 * (Playwright fixture pages) — no node:crypto, no DOM.
 */
import {
  canonicalChallengeBytes,
  type GhostChallenge,
} from "../src/protocol/challenge.js";
import { deriveGhostId } from "../src/protocol/identity.js";

export const FIXTURE_PRIVATE_KEY_PKCS8_HEX =
  "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

export const FIXTURE_PUBLIC_KEY_RAW_HEX =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

export const FIXTURE_PUBLIC_KEY_BASE64URL =
  "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

export const FIXTURE_GHOST_ID = "ghost_1_crhgcniramqtgfpib5uiaautocwdigbt";

/** expiresAt is 2100-01-01T00:00:00Z — the fixtures never expire in tests. */
export const UNBOUND_CHALLENGE: GhostChallenge = {
  version: 1,
  nonce: "dGVzdC1ub25jZS0wMDAwMDAwMDAwMDAwMDAwMDAwMDAw",
  audience: "https://ghost.test",
  action: "login",
  expiresAt: 4102444800000,
};

export const BOUND_CHALLENGE: GhostChallenge = {
  ...UNBOUND_CHALLENGE,
  action: "delete-note",
  ghostId: FIXTURE_GHOST_ID,
};

export const UNBOUND_CANONICAL_HEX =
  "0000000e67686f73742d70726f6f662d76310000002c6447567a644331756232356a5a5330774d4441774d4441774d4441774d4441774d4441774d4441774d4441770000001268747470733a2f2f67686f73742e74657374000000056c6f67696e0000000d3431303234343438303030303000000000";

export const UNBOUND_SIGNATURE_HEX =
  "75794a5bb0d9f9b5b2da813320032a80bd530975871f0f762583a599af095d9731d0d39b3dd58c96cfdcad5cdbcf5799dad4332f7e572312e1578a282ef5090a";

export const BOUND_CANONICAL_HEX =
  "0000000e67686f73742d70726f6f662d76310000002c6447567a644331756232356a5a5330774d4441774d4441774d4441774d4441774d4441774d4441774d4441770000001268747470733a2f2f67686f73742e746573740000000b64656c6574652d6e6f74650000000d343130323434343830303030300000002867686f73745f315f63726867636e6972616d71746766706962357569616175746f63776469676274";

export const BOUND_SIGNATURE_HEX =
  "e51bdd7c79f8eaa1c232aa6d58d86c5d2a316b0ed8f47f93e1a3dd1b7bf390c698cc5c2fdcd1a208ca1870939a53d9d3e526ed4c94952d20f3310e464c497f05";

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export interface VectorCheck {
  name: string;
  pass: boolean;
  detail?: string;
}

export interface VectorReport {
  pass: boolean;
  checks: VectorCheck[];
}

/**
 * Recomputes every pinned value with the implementation under test and the
 * given SubtleCrypto.
 *
 * Signatures are deliberately NOT compared byte-for-byte: RFC 8032 signing
 * is deterministic on paper, but engines may add hedging noise as
 * side-channel hardening (WebKit does), producing different — equally
 * valid — signatures for the same key and message. The portable contract
 * is: the pinned Node-produced signature verifies everywhere, and a fresh
 * in-engine signature round-trips. Treat signatures as opaque valid/invalid,
 * never as identifiers.
 */
export async function runVectorChecks(subtle: SubtleCrypto): Promise<VectorReport> {
  const checks: VectorCheck[] = [];
  const record = (name: string, actual: string, expected: string) => {
    const pass = actual === expected;
    checks.push(pass ? { name, pass } : { name, pass, detail: `got ${actual}` });
  };

  const publicKeyRaw = hexToBytes(FIXTURE_PUBLIC_KEY_RAW_HEX);
  record("ghost id", await deriveGhostId(publicKeyRaw, subtle), FIXTURE_GHOST_ID);

  const privateKey = await subtle.importKey(
    "pkcs8",
    hexToBytes(FIXTURE_PRIVATE_KEY_PKCS8_HEX),
    "Ed25519",
    false,
    ["sign"],
  );
  const publicKey = await subtle.importKey("raw", publicKeyRaw, "Ed25519", false, [
    "verify",
  ]);

  for (const [label, challenge, canonicalHex, signatureHex] of [
    ["unbound", UNBOUND_CHALLENGE, UNBOUND_CANONICAL_HEX, UNBOUND_SIGNATURE_HEX],
    ["bound", BOUND_CHALLENGE, BOUND_CANONICAL_HEX, BOUND_SIGNATURE_HEX],
  ] as const) {
    const canonical = canonicalChallengeBytes(challenge);
    record(`${label} canonical bytes`, bytesToHex(canonical), canonicalHex);

    const pinnedVerifies = await subtle.verify(
      "Ed25519",
      publicKey,
      hexToBytes(signatureHex),
      canonical,
    );
    checks.push({ name: `${label} pinned signature verifies`, pass: pinnedVerifies });

    const fresh = new Uint8Array(await subtle.sign("Ed25519", privateKey, canonical));
    const freshVerifies = await subtle.verify("Ed25519", publicKey, fresh, canonical);
    checks.push({ name: `${label} fresh signature round-trips`, pass: freshVerifies });
  }

  return { pass: checks.every((check) => check.pass), checks };
}
