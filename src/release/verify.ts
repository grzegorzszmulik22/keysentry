import type { HttpClient } from '../types.js';
import { verifyDetached } from '../security/index.js';
import { RELEASE_PUBLIC_KEYS, RELEASE_REPO } from './release-key.js';

export interface ReleaseVerifyResult {
  status: 'verified' | 'unconfigured' | 'bad-signature' | 'hash-mismatch' | 'not-found';
  checked: string[];
}

/** Explicit opt-in only. The caller supplies its egress-guarded HTTP client. */
export async function verifyRelease(opts: {
  http: HttpClient;
  version: string;
  bundleSha256: string;
  repo?: string;
  keys?: typeof RELEASE_PUBLIC_KEYS;
}): Promise<ReleaseVerifyResult> {
  const keys = opts.keys ?? RELEASE_PUBLIC_KEYS;
  if (keys.length === 0) return { status: 'unconfigured', checked: [] };
  const repo = opts.repo ?? RELEASE_REPO;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)
      || repo.split('/').some(part => part === '.' || part === '..')) {
    throw new TypeError('Release repository must be an owner/repository name.');
  }
  if (!/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/.test(opts.version)) {
    throw new TypeError('Release version must be a package version.');
  }
  const base = `https://github.com/${repo}/releases/download/${encodeURIComponent('v' + opts.version)}/`;
  const checked: string[] = [];
  async function download(file: string): Promise<string | null> {
    const url = base + file;
    checked.push(url);
    const response = await opts.http.request({ method: 'GET', url });
    if (response.status === 404) return null;
    if (response.status < 200 || response.status >= 300) {
      // Never include an untrusted response body in an error.
      throw new Error(`Release verification request failed (HTTP ${response.status}).`);
    }
    return response.text;
  }
  const sums = await download('SHA256SUMS');
  if (sums === null) return { status: 'not-found', checked };
  const signatureLine = await download('SHA256SUMS.sig');
  if (signatureLine === null) return { status: 'not-found', checked };

  const match = /^([a-f0-9]{16}) ([A-Za-z0-9+/]{86}==)\n$/.exec(signatureLine);
  if (!match) return { status: 'bad-signature', checked };
  const [, keyId, encoded] = match;
  const signature = Buffer.from(encoded!, 'base64');
  if (signature.length !== 64 || signature.toString('base64') !== encoded) {
    return { status: 'bad-signature', checked };
  }
  const message = Buffer.from('keysentry-release:v1\n' + sums, 'utf8');
  const valid = keys.some(key => key.keyId === keyId
    && verifyDetached(Buffer.from(key.publicKeyDer, 'base64'), message, signature));
  if (!valid) return { status: 'bad-signature', checked };

  const entries = sums.split(/\r?\n/).filter(line => line !== '').map(line => /^([a-f0-9]{64})  (.+)$/.exec(line));
  const bundleEntries = entries.filter(entry => entry?.[2] === 'keysentry.mjs');
  if (entries.some(entry => entry === null) || bundleEntries.length !== 1
      || bundleEntries[0]?.[1] !== opts.bundleSha256) {
    return { status: 'hash-mismatch', checked };
  }
  return { status: 'verified', checked };
}
