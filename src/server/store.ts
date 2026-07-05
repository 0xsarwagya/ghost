/**
 * Replay protection state. `consume` must atomically mark a nonce as used
 * and return false if it already was. Implementations may drop entries
 * once `expiresAt` has passed — expired challenges are rejected before the
 * store is consulted.
 */
export interface ChallengeStore {
  consume(nonce: string, expiresAt: number): Promise<boolean>;
}

export interface GhostCredential {
  ghostId: string;
  credentialId: string;
  publicKey: string;
  status?: "active" | "superseded" | "revoked";
}

export interface BrowserGhostCredential {
  id: string;
  credentialId: string;
  publicKey: string;
  status?: "active" | "superseded" | "revoked";
}

export interface GhostCredentialStore {
  isCredentialActive(
    ghostId: string,
    credentialId: string,
    publicKey: string,
  ): Promise<boolean>;
}

/**
 * Single-process replay protection. Suitable for one server process, tests,
 * and demos. Behind a load balancer or across restarts you need a shared
 * store (Redis, a database row with a unique constraint) — implement
 * ChallengeStore against it.
 */
export class InMemoryChallengeStore implements ChallengeStore {
  private readonly consumed = new Map<string, number>();
  private readonly now: () => number;

  constructor(options: { now?: () => number } = {}) {
    this.now = options.now ?? Date.now;
  }

  // Synchronous check-then-set — atomic on a single JS event loop.
  consume(nonce: string, expiresAt: number): Promise<boolean> {
    this.sweep();
    if (this.consumed.has(nonce)) {
      return Promise.resolve(false);
    }
    this.consumed.set(nonce, expiresAt);
    return Promise.resolve(true);
  }

  get size(): number {
    return this.consumed.size;
  }

  private sweep(): void {
    const now = this.now();
    for (const [nonce, expiresAt] of this.consumed) {
      if (expiresAt < now) {
        this.consumed.delete(nonce);
      }
    }
  }
}

export class InMemoryGhostCredentialStore implements GhostCredentialStore {
  private readonly credentials = new Map<string, GhostCredential>();

  register(credential: GhostCredential | BrowserGhostCredential): void {
    const normalized =
      "ghostId" in credential
        ? credential
        : { ...credential, ghostId: credential.id };
    this.credentials.set(this.key(normalized.ghostId, normalized.credentialId), {
      ...normalized,
      status: credential.status ?? "active",
    });
  }

  revoke(ghostId: string, credentialId: string): void {
    const key = this.key(ghostId, credentialId);
    const credential = this.credentials.get(key);
    if (credential !== undefined) {
      this.credentials.set(key, { ...credential, status: "revoked" });
    }
  }

  isCredentialActive(
    ghostId: string,
    credentialId: string,
    publicKey: string,
  ): Promise<boolean> {
    const credential = this.credentials.get(this.key(ghostId, credentialId));
    return Promise.resolve(
      credential !== undefined &&
        credential.publicKey === publicKey &&
        (credential.status ?? "active") === "active",
    );
  }

  private key(ghostId: string, credentialId: string): string {
    return `${ghostId}\u0000${credentialId}`;
  }
}
