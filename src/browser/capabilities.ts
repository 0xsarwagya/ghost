export interface GhostCapabilities {
  /** crypto.subtle exists in this runtime. */
  webCrypto: boolean;
  /** A non-extractable Ed25519 keypair can actually be generated. */
  ed25519: boolean;
  /** IndexedDB exists — persistence is possible in principle. */
  indexedDB: boolean;
  /** All of the above. */
  supported: boolean;
}

let cached: Promise<GhostCapabilities> | undefined;

/**
 * Reports what this runtime can do, so applications can render an honest
 * unsupported state instead of memorizing browser folklore. Ed25519
 * support is only detectable by attempting key generation, so the probe
 * runs once and is cached. Persistence itself is not probed — storage
 * failures surface as typed errors from createGhost.
 */
export function capabilities(cryptoApi?: Crypto): Promise<GhostCapabilities> {
  if (cryptoApi !== undefined) {
    return probe(cryptoApi);
  }
  cached ??= probe(globalThis.crypto);
  return cached;
}

async function probe(cryptoApi: Crypto | undefined): Promise<GhostCapabilities> {
  const webCrypto = cryptoApi?.subtle !== undefined;
  const indexedDB = globalThis.indexedDB !== undefined;
  let ed25519 = false;
  if (webCrypto) {
    try {
      await cryptoApi.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
      ed25519 = true;
    } catch {
      ed25519 = false;
    }
  }
  return {
    webCrypto,
    ed25519,
    indexedDB,
    supported: webCrypto && ed25519 && indexedDB,
  };
}
