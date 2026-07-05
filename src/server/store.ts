/**
 * Replay protection state. `consume` must atomically mark a nonce as used
 * and return false if it already was. Implementations may drop entries
 * once `expiresAt` has passed — expired challenges are rejected before the
 * store is consulted.
 */
export interface ChallengeStore {
  consume(nonce: string, expiresAt: number): Promise<boolean>;
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
