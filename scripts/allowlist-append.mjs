#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { lstat, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const GENESIS = '0'.repeat(64);
const ENTRY_DOMAIN = 'keysentry-allowlist:v1\n';
const HEAD_DOMAIN = 'keysentry-allowlist-head:v1\n';
const ENTRY_FIELDS = ['seq', 'digest', 'reference', 'addedAt', 'reason', 'prev', 'hash', 'sig'];
const HEAD_FIELDS = ['seq', 'hash', 'at', 'keyId', 'sig'];

// All signed values here are flat objects of validated strings and integers.
// This produces the same bytes as src/security/canonical.ts without requiring a
// TypeScript loader (this release tool runs directly under Node >=22.13).
function canonicalJson(value) {
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${JSON.stringify(value[key])}`).join(',')}}`;
}

function hashOf(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function readSigningKey(env) {
  const material = env.KEYSENTRY_RELEASE_SIGNING_KEY?.trim();
  if (!material) throw new Error('Set KEYSENTRY_RELEASE_SIGNING_KEY to an Ed25519 PKCS#8 DER private key encoded as base64.');
  let der;
  try {
    der = Buffer.from(material, 'base64');
    if (der.length === 0 || der.toString('base64') !== material) throw new Error();
    const key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    if (key.asymmetricKeyType !== 'ed25519') throw new Error();
    return key;
  } catch {
    throw new Error('KEYSENTRY_RELEASE_SIGNING_KEY must contain an Ed25519 PKCS#8 DER private key encoded as base64.');
  } finally {
    der?.fill(0);
  }
}

function isHash(value) {
  return typeof value === 'string' && value.length === 64 && /^[a-f0-9]{64}$/.test(value);
}

function isDigest(value) {
  return typeof value === 'string' && value.length === 71 && /^sha256:[a-fA-F0-9]{64}$/.test(value);
}

function isText(value) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= 4096;
}

function isTime(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) return false;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return false;
  const normalized = value.replace(/(?:\.(\d{1,3}))?Z$/, (_, fraction) => `.${(fraction ?? '').padEnd(3, '0')}Z`);
  return parsed.toISOString() === normalized;
}

function exactFields(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}

function validSignature(publicKey, data, signature) {
  if (typeof signature !== 'string') return false;
  const bytes = Buffer.from(signature, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== signature) return false;
  return verify(null, Buffer.from(data), publicKey, bytes);
}

async function readPublicFile(path, maxBytes) {
  let stats;
  try {
    stats = await lstat(path);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  if (!stats.isFile() || stats.size > maxBytes) throw new Error('The allow-list history must use regular files within the supported size.');
  return readFile(path, 'utf8');
}

function checkedHistory(log, headText, publicKey, keyId) {
  if (log === null && headText === null) return { seq: 0, hash: GENESIS, at: null };
  const invalid = () => new Error('The existing allow-list history or signed head could not be verified.');
  if (log === null || headText === null) throw invalid();
  try {
    const lines = log.split(/\r?\n/);
    if (lines.at(-1) === '') lines.pop();
    let previous = { seq: 0, hash: GENESIS, at: null };
    for (const line of lines) {
      const entry = JSON.parse(line);
      if (!exactFields(entry, ENTRY_FIELDS) || !Number.isSafeInteger(entry.seq) || entry.seq !== previous.seq + 1
        || !isDigest(entry.digest) || !isText(entry.reference) || !isText(entry.reason) || !isTime(entry.addedAt)
        || !isHash(entry.prev) || !isHash(entry.hash) || entry.prev !== previous.hash
        || (previous.at !== null && Date.parse(entry.addedAt) < Date.parse(previous.at))) throw invalid();
      const payload = { seq: entry.seq, digest: entry.digest, reference: entry.reference, addedAt: entry.addedAt, reason: entry.reason, prev: entry.prev };
      if (hashOf(payload) !== entry.hash || !validSignature(publicKey, `${ENTRY_DOMAIN}${entry.hash}`, entry.sig)) throw invalid();
      previous = { seq: entry.seq, hash: entry.hash, at: entry.addedAt };
    }
    const head = JSON.parse(headText);
    if (!exactFields(head, HEAD_FIELDS) || !Number.isSafeInteger(head.seq) || head.seq < 0
      || head.seq !== previous.seq || !isHash(head.hash) || head.hash !== previous.hash || !isTime(head.at)
      || head.keyId !== keyId || (previous.at !== null && Date.parse(head.at) < Date.parse(previous.at))
      || !validSignature(publicKey, `${HEAD_DOMAIN}${canonicalJson({ seq: head.seq, hash: head.hash, at: head.at })}`, head.sig)) throw invalid();
    return { seq: head.seq, hash: head.hash, at: head.at };
  } catch {
    throw invalid();
  }
}

/**
 * Extend locally verified history, preserving existing bytes. Only the current
 * release public key is trusted by this standalone tool; key rotation requires a
 * deliberate tool update, rather than trusting key material from the public log.
 */
export async function appendAllowList(options, env = process.env) {
  if (!isDigest(options.digest)) throw new Error('The image digest must be sha256 followed by 64 hexadecimal characters.');
  if (!isText(options.reference) || !isText(options.reason)) throw new Error('The allow-list reference and reason must be nonempty text.');
  const at = options.at instanceof Date ? options.at.toISOString() : (options.at ?? new Date().toISOString());
  if (!isTime(at)) throw new Error('The allow-list time must be a valid UTC ISO timestamp.');
  if (typeof options.logPath !== 'string' || typeof options.headPath !== 'string') throw new Error('Provide paths for the allow-list log and head.');
  const logPath = resolve(options.logPath);
  const headPath = resolve(options.headPath);
  const comparableLogPath = process.platform === 'win32' ? logPath.toLowerCase() : logPath;
  const comparableHeadPath = process.platform === 'win32' ? headPath.toLowerCase() : headPath;
  if (comparableLogPath === comparableHeadPath) throw new Error('The allow-list log and head must use different files.');
  const privateKey = readSigningKey(env);
  const publicKey = createPublicKey(privateKey);
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const keyId = createHash('sha256').update(publicDer).digest('hex').slice(0, 16);
  await mkdir(dirname(logPath), { recursive: true });
  await mkdir(dirname(headPath), { recursive: true });
  const lockPath = `${logPath}.lock`;
  let lock;
  try {
    lock = await open(lockPath, 'wx', 0o600);
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error('Another allow-list writer is in progress; check the writer lock before retrying.');
    throw error;
  }
  let temporaryHead;
  try {
    const log = await readPublicFile(logPath, 16 * 1024 * 1024);
    const headText = await readPublicFile(headPath, 8192);
    const previous = checkedHistory(log, headText, publicKey, keyId);
    if (previous.at !== null && Date.parse(at) < Date.parse(previous.at)) throw new Error('The new allow-list time cannot precede the signed head time.');
    if (!Number.isSafeInteger(previous.seq + 1)) throw new Error('The allow-list sequence is outside the supported range.');
    const payload = { seq: previous.seq + 1, digest: options.digest, reference: options.reference, addedAt: at, reason: options.reason, prev: previous.hash };
    const hash = hashOf(payload);
    const entry = { ...payload, hash, sig: sign(null, Buffer.from(`${ENTRY_DOMAIN}${hash}`), privateKey).toString('base64') };
    const headPayload = { seq: entry.seq, hash, at };
    const head = { ...headPayload, keyId, sig: sign(null, Buffer.from(`${HEAD_DOMAIN}${canonicalJson(headPayload)}`), privateKey).toString('base64') };
    // Two public files cannot be committed atomically together. Flush the append
    // first, then replace the head. An interrupted update therefore fails closed
    // at verification, rather than silently overwriting or dropping history.
    const logFile = await open(logPath, 'a', 0o644);
    try {
      await logFile.writeFile(`${log && !log.endsWith('\n') ? '\n' : ''}${canonicalJson(entry)}\n`);
      await logFile.sync();
    } finally {
      await logFile.close();
    }
    temporaryHead = `${headPath}.${randomBytes(12).toString('hex')}.tmp`;
    const headFile = await open(temporaryHead, 'wx', 0o644);
    try {
      await headFile.writeFile(`${canonicalJson(head)}\n`);
      await headFile.sync();
    } finally {
      await headFile.close();
    }
    await rename(temporaryHead, headPath);
    temporaryHead = undefined;
    return { entry, head };
  } finally {
    if (temporaryHead) await unlink(temporaryHead).catch(() => {});
    await lock.close();
    await unlink(lockPath);
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const args = process.argv.slice(2);
    if (![3, 5].includes(args.length) || args[0].startsWith('-')) {
      throw new Error('Usage: node scripts/allowlist-append.mjs <digest> <reference> <reason> [logPath headPath]');
    }
    await appendAllowList({
      digest: args[0], reference: args[1], reason: args[2],
      logPath: args[3] ?? fileURLToPath(new URL('../allowlist/log.jsonl', import.meta.url)),
      headPath: args[4] ?? fileURLToPath(new URL('../allowlist/head.json', import.meta.url)),
    });
  } catch (error) {
    console.error(error.code ? 'keysentry could not read or update the allow-list files.' : error.message);
    process.exitCode = 1;
  }
}
