import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { BoxSealMode, HttpClient } from '../../types.js';
import { openBytes, sealBytes } from '../../security/index.js';
import { assertKeyName, kmsDecrypt, kmsEncrypt } from './kms.js';
import { assertAudience, exchangeForAccessToken } from './sts.js';
import { assertDeviceShare, deriveUnlockDataKey } from './unlock.js';
import { syncFile } from '../../security/durable.js';

export const DEFAULT_ATTESTATION_TOKEN_PATH = '/run/container_launcher/attestation_verifier_claims_token';
export const MAX_BOX_BUNDLE_BYTES = 1024 * 1024;
const MAX_STATE_BYTES = 2 * 1024 * 1024;
const OPEN_FAILED = 'Could not open the sealed box bundle. Check the box config, device share, and saved state.';

/** These settings must come from the authenticated, sealed box config, never the on-disk ciphertext record. */
export interface BoxSealConfig {
  boxId: string;
  mode: BoxSealMode;
  audience: string;
  keyName: string;
}

export interface BoxSealOptions {
  http: HttpClient;
  stateDir: string;
  config: BoxSealConfig;
  attestationTokenPath?: string;
  readAttestationToken?: (path: string) => Promise<string>;
  /** Once per locked episode. The caller owns notification delivery/retries; errors do not change locked status. */
  onLocked?: () => void | Promise<void>;
}

export type OpenSealedResult = { status: 'open'; bundle: Buffer } | { status: 'locked' };

export interface BoxSealer {
  /** Caller retains ownership of the input buffer. Supply share B initially in unlock-on-restart mode. */
  sealBundle(bundle: Buffer, shareB?: Buffer): Promise<void>;
  /** An open result contains caller-owned plaintext; the caller must clear it when no longer needed. */
  openSealed(shareB?: Buffer): Promise<OpenSealedResult>;
  /** Clear the in-memory device share. No key or share is written to disk. */
  lock(): Promise<void>;
}

interface RecordV1 {
  version: 1;
  mode: BoxSealMode;
  wrappedKey: string;
  sealedBundle: string;
}

function decode(value: unknown, max: number): Buffer {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(max / 3) * 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error(OPEN_FAILED);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > max || bytes.toString('base64') !== value) throw new Error(OPEN_FAILED);
  return bytes;
}

async function readRecord(path: string, mode: BoxSealMode): Promise<{ wrappedKey: Buffer; sealedBundle: Buffer }> {
  try {
    if ((await lstat(path)).isSymbolicLink()) throw new Error();
    const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const info = await handle.stat();
      if (!info.isFile() || info.size > MAX_STATE_BYTES) throw new Error();
      // Bounded even if another process grows the file after stat.
      const bytes = Buffer.alloc(info.size + 1);
      let length = 0;
      while (length < bytes.length) {
        const result = await handle.read(bytes, length, bytes.length - length, null);
        if (result.bytesRead === 0) break;
        length += result.bytesRead;
      }
      if (length !== info.size) throw new Error();
      const record: unknown = JSON.parse(bytes.subarray(0, length).toString('utf8'));
      if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error();
      const body = record as Partial<RecordV1>;
      if (body.version !== 1 || body.mode !== mode) throw new Error();
      return { wrappedKey: decode(body.wrappedKey, 128 * 1024), sealedBundle: decode(body.sealedBundle, MAX_BOX_BUNDLE_BYTES + 32) };
    } finally { await handle.close(); }
  } catch { throw new Error(OPEN_FAILED); }
}

async function writeRecord(dir: string, path: string, record: RecordV1): Promise<void> {
  const temporary = join(dir, `.sealed-bundle-${randomBytes(16).toString('hex')}.tmp`);
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    try {
      await handle.writeFile(JSON.stringify(record) + '\n', 'utf8');
      await syncFile(handle);
    } finally { await handle.close(); }
    // Both ciphertexts commit together, so a failed wrap/write cannot replace just half of the pair.
    await rename(temporary, path);
    if (process.platform !== 'win32') {
      const directory = await open(dir, constants.O_RDONLY);
      try { await syncFile(directory); } finally { await directory.close(); }
    }
  } catch { throw new Error('Could not store the sealed box bundle. Check the box state directory.'); }
  finally { await unlink(temporary).catch(() => undefined); }
}

/** Shared envelope scheme for standard, customer KMS, and unlock-on-restart configurations. */
export function createBoxSealer(options: BoxSealOptions): BoxSealer {
  const config = { ...options.config };
  if (typeof config.boxId !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(config.boxId)) throw new Error('The box id is invalid.');
  if (!['standard', 'byo-kms', 'unlock-on-restart'].includes(config.mode)) throw new Error('The box seal mode is invalid.');
  assertAudience(config.audience);
  assertKeyName(config.keyName);
  if (typeof options.stateDir !== 'string' || !options.stateDir || options.stateDir.includes('\0')) throw new Error('The box state directory is invalid.');
  const dir = resolve(options.stateDir);
  const path = join(dir, 'sealed-bundle.json');
  const tokenPath = options.attestationTokenPath ?? DEFAULT_ATTESTATION_TOKEN_PATH;
  const readToken = options.readAttestationToken ?? ((file: string) => readFile(file, 'utf8'));
  const { http, onLocked } = options;
  const aad = Buffer.from(`keysentry-box-dek:v1:${config.boxId}`, 'utf8');
  const bundleAad = `keysentry-box-bundle:v1:${config.boxId}:${config.mode}`;
  let deviceShare: Buffer | undefined;
  let lockedNoticeSent = false;
  let pending: Promise<unknown> = Promise.resolve();

  function enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const next = pending.catch(() => undefined).then(operation);
    pending = next;
    return next;
  }

  async function accessToken(): Promise<string> {
    let subjectToken: string;
    try { subjectToken = (await readToken(tokenPath)).trim(); }
    catch { throw new Error('Could not read the box attestation token. Check the launcher token file.'); }
    return exchangeForAccessToken(http, { audience: config.audience, subjectToken });
  }

  function candidateShare(supplied?: Buffer): Buffer | undefined {
    if (config.mode !== 'unlock-on-restart') {
      if (supplied !== undefined) throw new Error('A device share is only used in unlock-on-restart mode.');
      return undefined;
    }
    if (supplied !== undefined) { assertDeviceShare(supplied); return Buffer.from(supplied); }
    return deviceShare === undefined ? undefined : Buffer.from(deviceShare);
  }

  function rememberShare(share: Buffer | undefined): void {
    deviceShare?.fill(0);
    deviceShare = share === undefined ? undefined : Buffer.from(share);
    lockedNoticeSent = false;
  }

  return {
    sealBundle(bundle, shareB) {
      return enqueue(async () => {
        if (!Buffer.isBuffer(bundle) || bundle.length > MAX_BOX_BUNDLE_BYTES) throw new Error('The box token bundle must be bytes and at most 1 MiB.');
        const share = candidateShare(shareB);
        if (config.mode === 'unlock-on-restart' && share === undefined) throw new Error('The box needs the device share before sealing in unlock-on-restart mode.');
        let wrappingMaterial: Buffer | undefined;
        let dataKey: Buffer | undefined;
        try {
          const access = await accessToken();
          wrappingMaterial = randomBytes(32);
          dataKey = share === undefined ? Buffer.from(wrappingMaterial) : deriveUnlockDataKey(wrappingMaterial, config.boxId, share);
          const wrapped = await kmsEncrypt(http, access, config.keyName, wrappingMaterial, aad);
          const sealed = sealBytes(dataKey, bundle, bundleAad);
          await writeRecord(dir, path, { version: 1, mode: config.mode, wrappedKey: wrapped.toString('base64'), sealedBundle: sealed.toString('base64') });
          rememberShare(share);
        } finally { wrappingMaterial?.fill(0); dataKey?.fill(0); share?.fill(0); }
      });
    },
    openSealed(shareB) {
      return enqueue(async () => {
        const share = candidateShare(shareB);
        let wrappingMaterial: Buffer | undefined;
        let dataKey: Buffer | undefined;
        try {
          const record = await readRecord(path, config.mode);
          if (config.mode === 'unlock-on-restart' && share === undefined) {
            if (!lockedNoticeSent) {
              lockedNoticeSent = true;
              try { await onLocked?.(); } catch { /* Notification delivery must not change the locked state. */ }
            }
            return { status: 'locked' };
          }
          wrappingMaterial = await kmsDecrypt(http, await accessToken(), config.keyName, record.wrappedKey, aad);
          if (wrappingMaterial.length !== 32) throw new Error('KMS returned an invalid box key length.');
          dataKey = share === undefined ? Buffer.from(wrappingMaterial) : deriveUnlockDataKey(wrappingMaterial, config.boxId, share);
          let bundle: Buffer;
          try { bundle = openBytes(dataKey, record.sealedBundle, bundleAad); }
          catch { throw new Error(OPEN_FAILED); }
          rememberShare(share);
          return { status: 'open', bundle };
        } finally { wrappingMaterial?.fill(0); dataKey?.fill(0); share?.fill(0); }
      });
    },
    lock() { return enqueue(async () => { if (deviceShare !== undefined) rememberShare(undefined); }); },
  };
}
