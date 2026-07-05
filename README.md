# Ghost

Persistent cryptographic identity for web apps without accounts.

A TypeScript library that gives a browser a keypair instead of giving your
application a user database. The private key never leaves the browser. The
browser gets a stable Ghost ID, and the active public key becomes a
credential for that Ghost. Your server verifies signatures.

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
console.log(ghost.credentialId); // cred_1_…

// Later, prove possession of a server-issued challenge:
const proof = await ghost.sign(challenge);
```

On your server:

```ts
import {
  createChallenge,
  InMemoryChallengeStore,
  InMemoryGhostCredentialStore,
  verifyGhostProof,
} from "@0xsarwagya/ghost/server";

const store = new InMemoryChallengeStore();
const credentials = new InMemoryGhostCredentialStore();
credentials.register(ghost); // persist this in your own database in production

// 1. Issue a one-time challenge.
const challenge = createChallenge({ audience: "https://app.example", action: "login" });

// 2. Verify the browser's proof.
const result = await verifyGhostProof(proof, {
  expectedAudience: "https://app.example",
  challengeStore: store,
  credentialStore: credentials,
});

if (result.ok) {
  console.log("same ghost as before:", result.ghostId);
}
```

No email. No password. No OAuth. No user table.

## Optional recovery

Ghost is usable without recovery. When a Ghost owns durable value, ask the
user whether to make it recoverable:

```ts
const { recoverySecret, recoveryRecord } = await ghost.enableRecovery();
// Show recoverySecret once. Store recoveryRecord with your app's Ghost row.
```

If the browser profile is lost, the user supplies the secret and your app
supplies the recovery record:

```ts
import { recoverGhost } from "@0xsarwagya/ghost";

const ghost = await recoverGhost({ recoverySecret, recoveryRecord });
// Same ghost.id, fresh non-extractable credential.
```

## Used in Local

[Local](https://local.sarwagya.wtf) uses Ghost as the identity primitive
between two chatting browsers. Each peer signs a nonce chosen by the
other; the resulting proofs establish mutual identity before any message
crosses the WebRTC data channel. The conversation history is pinned to
the peer's Ghost ID.

Source: [github.com/0xsarwagya/local](https://github.com/0xsarwagya/local)

## Status

Experimental. The protocol is versioned and the v1 wire format is pinned by
test vectors, but the API may still change before 1.0. Read the
[security model](https://oss.sarwagya.wtf/ghost/docs/security) before
relying on it — especially what Ghost does not prove.

## Documentation

https://oss.sarwagya.wtf/ghost/docs

## License

[MIT](./LICENSE)
