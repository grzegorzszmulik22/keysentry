import { generateKeyPairSync, randomBytes, sign, X509Certificate, type JsonWebKey, type KeyObject } from 'node:crypto';

function der(tag: number, bytes: Buffer): Buffer {
  let length: Buffer;
  if (bytes.length < 128) length = Buffer.from([bytes.length]);
  else {
    const hex = bytes.length.toString(16).padStart(Math.ceil(bytes.length.toString(16).length / 2) * 2, '0');
    const size = Buffer.from(hex, 'hex');
    length = Buffer.concat([Buffer.from([0x80 | size.length]), size]);
  }
  return Buffer.concat([Buffer.from([tag]), length, bytes]);
}
const sequence = (...parts: Buffer[]) => der(0x30, Buffer.concat(parts));
const oid = (hex: string) => der(0x06, Buffer.from(hex, 'hex'));
const algorithm = sequence(oid('2a864886f70d01010b'), der(0x05, Buffer.alloc(0)));
const name = (cn: string) => sequence(der(0x31, sequence(oid('550403'), der(0x0c, Buffer.from(cn)))));
const time = (date: Date) => der(0x18, Buffer.from(date.toISOString().replace(/[-:]/g, '').replace('T', '').slice(0, 14) + 'Z'));

function certificate(subject: string, issuer: string, publicKey: KeyObject, signer: KeyObject,
  ca: boolean, from: Date, to: Date, serial: number): X509Certificate {
  const constraints = sequence(oid('551d13'), der(0x01, Buffer.from([0xff])),
    der(0x04, ca ? sequence(der(0x01, Buffer.from([0xff]))) : sequence()));
  const body = sequence(der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, Buffer.from([serial])),
    algorithm, name(issuer), sequence(time(from), time(to)), name(subject),
    publicKey.export({ format: 'der', type: 'spki' }), der(0xa3, sequence(constraints)));
  return new X509Certificate(sequence(body, algorithm,
    der(0x03, Buffer.concat([Buffer.from([0]), sign('RSA-SHA256', body, signer)]))));
}

export interface EmulatorPki {
  privateKey: KeyObject;
  jwks: JsonWebKey[];
  root: X509Certificate;
  /** Standard-base64 DER certificates in leaf, intermediate, root order. */
  chain: string[];
  kid: string;
}

/** Ephemeral local CA material; never a Google trust anchor. Nothing is persisted. */
export function createEmulatorPki(now: Date): EmulatorPki {
  const timestamp = now.getTime();
  if (!Number.isFinite(timestamp)) throw new TypeError('Invalid emulator clock.');
  const from = new Date(timestamp - 86_400_000);
  const to = new Date(timestamp + 366 * 86_400_000);
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime())) throw new TypeError('Invalid emulator clock.');
  const rootKeys = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
  const intermediateKeys = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
  const leafKeys = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
  const root = certificate('keysentry emulator root', 'keysentry emulator root', rootKeys.publicKey, rootKeys.privateKey, true, from, to, 1);
  const intermediate = certificate('keysentry emulator intermediate', 'keysentry emulator root', intermediateKeys.publicKey, rootKeys.privateKey, true, from, to, 2);
  const leaf = certificate('keysentry emulator signer', 'keysentry emulator intermediate', leafKeys.publicKey, intermediateKeys.privateKey, false, from, to, 3);
  const kid = randomBytes(16).toString('hex');
  return { privateKey: leafKeys.privateKey, root, kid,
    jwks: [{ ...leafKeys.publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' }],
    chain: [leaf, intermediate, root].map(cert => cert.raw.toString('base64')) };
}
