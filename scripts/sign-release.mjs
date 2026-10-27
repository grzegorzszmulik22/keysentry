#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

function keyId(publicKeyDer) {
  return createHash('sha256').update(publicKeyDer).digest('hex').slice(0, 16);
}

function readSigningKey(env) {
  const material = env.KEYSENTRY_RELEASE_SIGNING_KEY?.trim();
  if (!material) throw new Error('Set KEYSENTRY_RELEASE_SIGNING_KEY to an Ed25519 PKCS#8 DER private key encoded as base64.');
  let privateDer;
  try {
    privateDer = Buffer.from(material, 'base64');
    if (privateDer.length === 0 || privateDer.toString('base64') !== material) throw new Error();
    const privateKey = createPrivateKey({ key: privateDer, format: 'der', type: 'pkcs8' });
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error();
    return privateKey;
  } catch {
    throw new Error('KEYSENTRY_RELEASE_SIGNING_KEY must contain an Ed25519 PKCS#8 DER private key encoded as base64.');
  } finally {
    privateDer?.fill(0);
  }
}

async function checkedArtifacts(sumsPath) {
  const path = resolve(sumsPath);
  if (!(await lstat(path)).isFile()) throw new Error('Release checksums must be a regular file.');
  const checksums = await readFile(path);
  if (checksums.length > 16384) throw new Error('Release checksums are not valid.');
  const entries = checksums.toString('utf8').split(/\r?\n/);
  if (entries.pop() !== '') throw new Error('Release checksums are not valid.');
  const files = new Map();
  for (const line of entries) {
    const match = /^([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)$/.exec(line);
    if (!match || files.has(match[2])) throw new Error('Release checksums are not valid.');
    files.set(match[2], match[1]);
  }
  const tarballs = [...files.keys()].filter(name => /^keysentry-[0-9][A-Za-z0-9.+-]*\.tgz$/.test(name));
  if (files.size !== 3 || !files.has('keysentry.mjs') || !files.has('release-manifest.json') || tarballs.length !== 1) {
    throw new Error('Release checksums must list the bundle, manifest and one package tarball.');
  }
  for (const [name, expected] of files) {
    const artifact = join(dirname(path), name);
    if (!(await lstat(artifact)).isFile()) throw new Error('A release artifact is not a regular file.');
    const actual = createHash('sha256').update(await readFile(artifact)).digest('hex');
    if (actual !== expected) throw new Error('A release artifact does not match its checksum.');
  }
  return { checksums, count: files.size };
}

/** Re-hash downloaded artifacts using Node built-ins; never execute build output. */
export async function verifyReleaseArtifacts(sumsPath) {
  return (await checkedArtifacts(sumsPath)).count;
}

export async function signRelease(sumsPath, env = process.env) {
  // Recheck here as well so invoking the signer directly cannot skip verification.
  const { checksums } = await checkedArtifacts(sumsPath);
  const privateKey = readSigningKey(env);
  const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const signature = sign(null, Buffer.concat([Buffer.from('keysentry-release:v1\n', 'utf8'), checksums]), privateKey);
  const signaturePath = `${sumsPath}.sig`;
  await writeFile(signaturePath, `${keyId(publicDer)} ${signature.toString('base64')}\n`);
  return signaturePath;
}

function printNewKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  try {
    // This is the only command that prints private material. Store its private
    // value in the release secret and publish only publicKeyDer and keyId.
    process.stdout.write(`${JSON.stringify({
      KEYSENTRY_RELEASE_SIGNING_KEY: privateDer.toString('base64'),
      publicKeyDer: publicDer.toString('base64'),
      keyId: keyId(publicDer),
    }, null, 2)}\n`);
  } finally {
    privateDer.fill(0);
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const args = process.argv.slice(2);
    if (args.length === 1 && args[0] === '--generate') {
      printNewKeyPair();
    } else if (args[0] === '--verify' && args.length === 2) {
      await verifyReleaseArtifacts(resolve(args[1]));
    } else {
      if (args.length > 1 || args[0]?.startsWith('-')) throw new Error('Usage: node scripts/sign-release.mjs [SHA256SUMS path], --verify <SHA256SUMS path> or --generate');
      const defaultPath = fileURLToPath(new URL('../dist-release/out/SHA256SUMS', import.meta.url));
      await signRelease(args[0] ? resolve(args[0]) : defaultPath);
    }
  } catch (error) {
    console.error(error.code ? 'keysentry could not read the checksums or write their signature.' : error.message);
    process.exitCode = 1;
  }
}
