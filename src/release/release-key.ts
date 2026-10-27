export { RELEASE_REPO } from './build-info.js';

// A maintainer must provision an offline Ed25519 key before online verification
// can establish a release's publisher. An empty list must never mean verified.
export const RELEASE_PUBLIC_KEYS: readonly { keyId: string; publicKeyDer: string }[] = [];
