import { canonicalJson, openBytes, sealBytes } from '../security/index.js';
import { MAX_WATCHER_CONFIG_BYTES, parseWatcherConfig, type WatcherConfig } from './config.js';

const AAD = 'keysentry-watcher-config:v1';
const PREFIX = 'ksw1.';
const OPEN_FAILED = 'Could not open the watcher config. Check KEYSENTRY_WATCHER_KEY or run keysentry watcher setup again.';

export function sealWatcherConfig(config: WatcherConfig, deployKey: Buffer): string {
  if (!Buffer.isBuffer(deployKey) || deployKey.length !== 32) throw new TypeError('The watcher deploy key must be exactly 32 bytes.');
  let plaintext: Buffer | undefined;
  try {
    const parsed = parseWatcherConfig(config);
    plaintext = Buffer.from(canonicalJson(parsed), 'utf8');
    if (plaintext.length > MAX_WATCHER_CONFIG_BYTES) throw new Error();
    return PREFIX + sealBytes(deployKey, plaintext, AAD).toString('base64url');
  } catch { throw new Error('Could not seal the watcher config. Check its settings.'); }
  finally { plaintext?.fill(0); }
}

export function openWatcherConfig(sealed: string, deployKey: Buffer): WatcherConfig {
  let plaintext: Buffer | undefined;
  try {
    if (typeof sealed !== 'string' || sealed.length > MAX_WATCHER_CONFIG_BYTES * 2 || !sealed.startsWith(PREFIX)) throw new Error();
    const encoded = sealed.slice(PREFIX.length);
    if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error();
    const envelope = Buffer.from(encoded, 'base64url');
    if (envelope.toString('base64url') !== encoded || envelope.length > MAX_WATCHER_CONFIG_BYTES + 32) throw new Error();
    plaintext = openBytes(deployKey, envelope, AAD);
    if (plaintext.length > MAX_WATCHER_CONFIG_BYTES) throw new Error();
    return parseWatcherConfig(JSON.parse(plaintext.toString('utf8')));
  } catch { throw new Error(OPEN_FAILED); }
  finally { plaintext?.fill(0); }
}
