# Roadmap

Ghost is a small primitive and this is a small document. The product is
finished when an application can remember a returning browser without an
account system — most of what an auth platform ships is deliberately out of
scope here, forever.

## 0.1 — the continuity release (current)

The whole v1 protocol, proven across engines:

- Non-extractable Ed25519 keypair, persisted in IndexedDB, origin-bound.
- Versioned identity format (`ghost_1_…`) derived from the public key.
- Challenge → sign → verify with replay, expiry, audience, action, and
  identity-binding enforcement.
- Server verifier that runs anywhere `globalThis.crypto` exists.
- Deterministic test vectors pinned in-tree, recomputed in Chromium,
  Firefox, and WebKit in CI.

One honest finding from the lab: WebKit hedges Ed25519 signatures, so
signatures are not byte-reproducible across engines. The protocol treats
them as opaque valid/invalid, and so should you.

## 0.2 — proposed

**Named identities.** `createGhost({ name: "work" })` for applications that
genuinely need more than one identity per origin. Open question: whether
any real application asks for this before it exists.

**Storage durability report.** `capabilities()` could report
`navigator.storage.persist()` state so applications can warn before an
eviction surprises someone.

## 0.3 — proposed

**Request signing.** Signing individual requests (method, path, body hash)
instead of one-shot challenges. Canonicalization, clock skew, and streaming
bodies make this a real protocol project — it lands only if a real
application outgrows challenges.

## What I have decided not to build

- Email, passwords, OAuth, passkeys, SSO, organizations, or anything that
  makes Ghost an account system.
- Key export. A non-extractable key that becomes extractable on request is
  neither.
- Cross-device sync or recovery. If the browser loses the key, the identity
  is gone — that is the fundamental tradeoff, not a bug backlog item.
- A hosted Ghost service. There is no server to run; that absence is the
  product.
- DIDs, blockchains, zero-knowledge proofs.

## How to nudge this

Open an issue at https://github.com/0xsarwagya/ghost/issues describing the
application you are building. Features here ship when a real application is
blocked without them, not when the idea sounds elegant.
