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

/** Domain separation for legacy identity derivation — hashed before bytes. */
export const ID_CONTEXT = "ghost-id-v1:";

/** Domain separation for credential IDs — hashed before the public key. */
export const CREDENTIAL_ID_CONTEXT = "ghost-credential-v1:";

/** Domain separation for recovery authorities — hashed before the secret. */
export const RECOVERY_AUTHORITY_CONTEXT = "ghost-recovery-authority-v1:";

/** Domain separation for proofs — first field of the canonical signed bytes. */
export const PROOF_CONTEXT = "ghost-proof-v1";

export const GHOST_ID_PREFIX = "ghost_1_";

export const CREDENTIAL_ID_PREFIX = "cred_1_";

export const RECOVERY_SECRET_PREFIX = "ghost_recovery_1_";

/** SHA-256 digest truncated to 160 bits before base32 encoding. */
export const GHOST_ID_HASH_BYTES = 20;

/** 20 bytes of base32 → exactly 32 chars of a-z2-7. */
export const GHOST_ID_PATTERN = /^ghost_1_[a-z2-7]{32}$/;

export const CREDENTIAL_ID_PATTERN = /^cred_1_[a-z2-7]{32}$/;

/** Human-held recovery secret entropy. */
export const RECOVERY_SECRET_BYTES = 32;
