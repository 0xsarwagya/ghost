import { GhostError } from "../errors.js";
import {
  CREDENTIAL_ID_CONTEXT,
  CREDENTIAL_ID_PATTERN,
  CREDENTIAL_ID_PREFIX,
  GHOST_ID_HASH_BYTES,
  GHOST_ID_PATTERN,
  GHOST_ID_PREFIX,
  ID_CONTEXT,
  RECOVERY_AUTHORITY_CONTEXT,
  RECOVERY_SECRET_BYTES,
  RECOVERY_SECRET_PREFIX,
} from "./constants.js";
import { decodeBase64Url, encodeBase32, encodeBase64Url, utf8Bytes } from "./encoding.js";

function resolveSubtle(subtle: SubtleCrypto | undefined): SubtleCrypto {
  const resolved = subtle ?? globalThis.crypto?.subtle;
  if (resolved === undefined) {
    throw new GhostError({
      code: "UNSUPPORTED",
      message: "Web Crypto (crypto.subtle) is not available in this runtime.",
      operation: "deriveGhostId",
    });
  }
  return resolved;
}

async function digestId(
  prefix: string,
  contextValue: string,
  material: Uint8Array,
  subtle?: SubtleCrypto,
): Promise<string> {
  const context = utf8Bytes(contextValue);
  const input = new Uint8Array(context.length + material.length);
  input.set(context, 0);
  input.set(material, context.length);
  const digest = await resolveSubtle(subtle).digest("SHA-256", input);
  const truncated = new Uint8Array(digest).slice(0, GHOST_ID_HASH_BYTES);
  return prefix + encodeBase32(truncated);
}

/**
 * Stable ghost ID from identity material. New identities use random material
 * so a Ghost can rotate credentials without changing this app-facing ID.
 */
export function createGhostId(
  identityMaterial: Uint8Array,
  subtle?: SubtleCrypto,
): Promise<string> {
  return digestId(GHOST_ID_PREFIX, ID_CONTEXT, identityMaterial, subtle);
}

/**
 * Legacy public-key fingerprint. Kept as an exported primitive for protocol
 * vectors and for callers migrating pre-recovery identities.
 */
export function deriveGhostId(
  publicKeyRaw: Uint8Array,
  subtle?: SubtleCrypto,
): Promise<string> {
  return createGhostId(publicKeyRaw, subtle);
}

export function deriveCredentialId(
  publicKeyRaw: Uint8Array,
  subtle?: SubtleCrypto,
): Promise<string> {
  return digestId(CREDENTIAL_ID_PREFIX, CREDENTIAL_ID_CONTEXT, publicKeyRaw, subtle);
}

export function isGhostId(value: string): boolean {
  return GHOST_ID_PATTERN.test(value);
}

export function isCredentialId(value: string): boolean {
  return CREDENTIAL_ID_PATTERN.test(value);
}

/**
 * Parses any ghost identifier shape and reports its protocol version, or
 * null when the string is not a ghost ID at all. Version 1 additionally
 * requires the exact v1 grammar.
 */
export function parseGhostId(value: string): { version: number } | null {
  const match = /^ghost_([1-9][0-9]*)_[a-z2-7]+$/.exec(value);
  if (match === null || match[1] === undefined) {
    return null;
  }
  const version = Number.parseInt(match[1], 10);
  if (version === 1 && !GHOST_ID_PATTERN.test(value)) {
    return null;
  }
  return { version };
}

export interface GhostRecoveryRecord {
  version: 1;
  method: "recovery-secret";
  ghostId: string;
  authorityId: string;
  createdAt: number;
}

export interface GhostRecoverySetup {
  recoverySecret: string;
  recoveryRecord: GhostRecoveryRecord;
}

export function createRecoverySecret(cryptoApi: Crypto): string {
  const bytes = new Uint8Array(RECOVERY_SECRET_BYTES);
  cryptoApi.getRandomValues(bytes);
  return RECOVERY_SECRET_PREFIX + encodeBase64Url(bytes);
}

export async function deriveRecoveryAuthorityId(
  recoverySecret: string,
  subtle?: SubtleCrypto,
): Promise<string> {
  if (!recoverySecret.startsWith(RECOVERY_SECRET_PREFIX)) {
    throw new GhostError({
      code: "RECOVERY_FAILED",
      message: "recovery secret has the wrong prefix",
      operation: "recoverGhost",
    });
  }
  let secret: Uint8Array;
  try {
    secret = decodeBase64Url(recoverySecret.slice(RECOVERY_SECRET_PREFIX.length));
  } catch (error) {
    throw new GhostError({
      code: "RECOVERY_FAILED",
      message: "recovery secret is not valid base64url",
      operation: "recoverGhost",
      cause: error,
    });
  }
  if (secret.length !== RECOVERY_SECRET_BYTES) {
    throw new GhostError({
      code: "RECOVERY_FAILED",
      message: "recovery secret has the wrong length",
      operation: "recoverGhost",
    });
  }
  return digestId("recauth_1_", RECOVERY_AUTHORITY_CONTEXT, secret, subtle);
}

export function assertRecoveryRecord(
  value: unknown,
  operation: "enableRecovery" | "recoverGhost",
): asserts value is GhostRecoveryRecord {
  if (typeof value !== "object" || value === null) {
    throw new GhostError({
      code: "RECOVERY_FAILED",
      message: "recovery record must be an object",
      operation,
    });
  }
  const record = value as Record<string, unknown>;
  if (
    record.version !== 1 ||
    record.method !== "recovery-secret" ||
    typeof record.ghostId !== "string" ||
    !isGhostId(record.ghostId) ||
    typeof record.authorityId !== "string" ||
    !record.authorityId.startsWith("recauth_1_") ||
    typeof record.createdAt !== "number"
  ) {
    throw new GhostError({
      code: "RECOVERY_FAILED",
      message: "recovery record is malformed",
      operation,
    });
  }
}
