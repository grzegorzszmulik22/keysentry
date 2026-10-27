// Ed25519 device keys: sign audit checkpoints (and later plans and approvals) on this machine.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';

export interface DeviceKey {
  /** PKCS#8 DER. Stays in the vault. */
  privateKeyDer: Buffer;
  /** SPKI DER. */
  publicKeyDer: Buffer;
  /** First 16 hex characters of SHA-256 of `publicKeyDer`. */
  keyId: string;
}

function keyIdOf(publicKeyDer: Buffer): string {
  return createHash('sha256').update(publicKeyDer).digest('hex').slice(0, 16);
}

export function generateDeviceKey(): DeviceKey {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateKeyDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' });
  return { privateKeyDer, publicKeyDer, keyId: keyIdOf(publicKeyDer) };
}

export function deviceKeyFromPrivate(privateKeyDer: Buffer): DeviceKey {
  const privateKey = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new TypeError('Device key must be an Ed25519 private key.');
  const publicKeyDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return { privateKeyDer: Buffer.from(privateKeyDer), publicKeyDer, keyId: keyIdOf(publicKeyDer) };
}

export function signDetached(privateKeyDer: Buffer, data: Buffer): Buffer {
  const key = createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
  return sign(null, data, key);
}

/** False for a bad signature, another key or malformed input; never throws. */
export function verifyDetached(publicKeyDer: Buffer, data: Buffer, sig: Buffer): boolean {
  try {
    const key = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') return false;
    return verify(null, data, key, sig);
  } catch {
    return false;
  }
}
