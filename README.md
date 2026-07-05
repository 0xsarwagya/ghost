# Ghost

Persistent cryptographic identity for web apps without accounts.

A TypeScript library that gives a browser a keypair instead of giving your
application a user database. The private key never leaves the browser. The
public key becomes the identity. Your server verifies signatures.

Ghost authenticates a key, not a person.

## Install

```sh
pnpm add @0xsarwagya/ghost
```

## First identity

In the browser:

```ts
import { createGhost } from "@0xsarwagya/ghost";

const ghost = await createGhost();
console.log(ghost.id); // ghost_1_crhgcniramqtgfpib5uiaautocwdigbt

// Later, prove possession of a server-issued challenge:
const proof = await ghost.sign(challenge);
```

On your server:

```ts
import {
  createChallenge,
  InMemoryChallengeStore,
  verifyGhostProof,
} from "@0xsarwagya/ghost/server";

const store = new InMemoryChallengeStore();

// 1. Issue a one-time challenge.
const challenge = createChallenge({ audience: "https://app.example", action: "login" });

// 2. Verify the browser's proof.
const result = await verifyGhostProof(proof, {
  expectedAudience: "https://app.example",
  challengeStore: store,
});

if (result.ok) {
  console.log("same ghost as before:", result.ghostId);
}
```

No email. No password. No OAuth. No user table.

## Status

Experimental. The protocol is versioned and the v1 wire format is pinned by
test vectors, but the API may still change before 1.0. Read the
[security model](https://oss.sarwagya.wtf/ghost/docs/security) before
relying on it — especially what Ghost does not prove.

## Documentation

https://oss.sarwagya.wtf/ghost/docs

## License

[MIT](./LICENSE)
