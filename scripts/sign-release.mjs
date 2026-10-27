#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
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

export async function signRelease(sumsPath, env = process.env) {
  const privateKey = readSigningKey(env);
  const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const checksums = await readFile(sumsPath);
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
    } else {
      if (args.length > 1 || args[0]?.startsWith('-')) throw new Error('Usage: node scripts/sign-release.mjs [SHA256SUMS path] or --generate');
      const defaultPath = fileURLToPath(new URL('../dist-release/out/SHA256SUMS', import.meta.url));
      await signRelease(args[0] ? resolve(args[0]) : defaultPath);
    }
  } catch (error) {
    console.error(error.code ? 'keysentry could not read the checksums or write their signature.' : error.message);
    process.exitCode = 1;
  }
}
