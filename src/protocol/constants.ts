/**
 * Protocol v1 = Ed25519 signatures + SHA-256 identity derivation.
 * The `1` in every version-carrying string means exactly this suite.
 */
export const PROTOCOL_VERSION = 1;

export const ALGORITHM = "ed25519";

/** Raw Ed25519 public key length (RFC 8032). */
export const PUBLIC_KEY_BYTES = 32;

/** Ed25519 signature length. */
export const SIGNATURE_BYTES = 64;

/** Domain separation for identity derivation — hashed before the key bytes. */
export const ID_CONTEXT = "ghost-id-v1:";

/** Domain separation for proofs — first field of the canonical signed bytes. */
export const PROOF_CONTEXT = "ghost-proof-v1";

export const GHOST_ID_PREFIX = "ghost_1_";

/** SHA-256 digest truncated to 160 bits before base32 encoding. */
export const GHOST_ID_HASH_BYTES = 20;

/** 20 bytes of base32 → exactly 32 chars of a-z2-7. */
export const GHOST_ID_PATTERN = /^ghost_1_[a-z2-7]{32}$/;
