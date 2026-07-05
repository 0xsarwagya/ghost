import { GhostError, type GhostOperation } from "../errors.js";

const DB_NAME = "ghost";
const STORE_NAME = "identities";
const RECORD_KEY = "default";

/**
 * What actually lives in IndexedDB. The private key is a non-extractable
 * CryptoKey carried by structured clone — its raw bytes are never
 * observable from JavaScript. The raw public key is stored alongside it so
 * loading an identity never depends on re-exporting anything.
 */
export interface IdentityRecord {
  id: typeof RECORD_KEY;
  version: 1;
  algorithm: "ed25519";
  privateKey: CryptoKey;
  publicKeyRaw: ArrayBuffer;
  createdAt: number;
}

function storageError(operation: GhostOperation, cause: unknown): GhostError {
  return new GhostError({
    code: "STORAGE_UNAVAILABLE",
    message: "IndexedDB is unavailable or failed",
    operation,
    cause,
  });
}

function openDb(operation: GhostOperation): Promise<IDBDatabase> {
  if (globalThis.indexedDB === undefined) {
    return Promise.reject(storageError(operation, undefined));
  }
  return new Promise((resolve, reject) => {
    const request = globalThis.indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(storageError(operation, request.error));
    request.onblocked = () => reject(storageError(operation, undefined));
  });
}

export async function loadIdentity(
  operation: GhostOperation,
): Promise<unknown | undefined> {
  const db = await openDb(operation);
  try {
    return await new Promise((resolve, reject) => {
      const request = db
        .transaction(STORE_NAME, "readonly")
        .objectStore(STORE_NAME)
        .get(RECORD_KEY);
      request.onsuccess = () => resolve(request.result as unknown);
      request.onerror = () => reject(storageError(operation, request.error));
    });
  } finally {
    db.close();
  }
}

/**
 * Stores the record unless one already exists, and returns whichever record
 * won. The get-then-put runs inside a single readwrite transaction, so two
 * tabs racing to create an identity converge on one keypair — the loser's
 * fresh key is simply discarded, never persisted.
 */
export async function saveIdentityIfAbsent(
  record: IdentityRecord,
  operation: GhostOperation,
): Promise<unknown> {
  const db = await openDb(operation);
  try {
    return await new Promise((resolve, reject) => {
      const store = db
        .transaction(STORE_NAME, "readwrite")
        .objectStore(STORE_NAME);
      const existing = store.get(RECORD_KEY);
      existing.onsuccess = () => {
        if (existing.result !== undefined) {
          resolve(existing.result as unknown);
          return;
        }
        const put = store.put(record);
        put.onsuccess = () => resolve(record);
        put.onerror = () => reject(storageError(operation, put.error));
      };
      existing.onerror = () => reject(storageError(operation, existing.error));
    });
  } finally {
    db.close();
  }
}

export async function deleteIdentity(operation: GhostOperation): Promise<void> {
  const db = await openDb(operation);
  try {
    await new Promise<void>((resolve, reject) => {
      const request = db
        .transaction(STORE_NAME, "readwrite")
        .objectStore(STORE_NAME)
        .delete(RECORD_KEY);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(storageError(operation, request.error));
    });
  } finally {
    db.close();
  }
}
