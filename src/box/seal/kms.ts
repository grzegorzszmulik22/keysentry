import type { HttpClient, HttpResponse } from '../../types.js';

// Reflected Castagnoli polynomial; RFC 3720 Appendix B.4 wire checksums are little endian.
const CRC32C_TABLE = Uint32Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
  return crc >>> 0;
});

export function crc32c(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = (crc >>> 8) ^ CRC32C_TABLE[(crc ^ byte) & 0xff]!;
  return (crc ^ 0xffffffff) >>> 0;
}

export function assertKeyName(keyName: string): void {
  if (typeof keyName !== 'string' || keyName.length > 1024 ||
      !/^projects\/[A-Za-z0-9_-]+\/locations\/[A-Za-z0-9_-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+$/.test(keyName)) {
    throw new Error('The box KMS key name is invalid.');
  }
}

function checkedBytes(encoded: unknown, checksum: unknown): Buffer {
  let bytes: Buffer | undefined;
  try {
    if (typeof encoded !== 'string' || encoded.length > 192 * 1024 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw new Error();
    bytes = Buffer.from(encoded, 'base64');
    if (bytes.toString('base64') !== encoded) throw new Error();
    if ((typeof checksum !== 'string' || !/^\d+$/.test(checksum)) && typeof checksum !== 'number') throw new Error();
    const expected = Number(checksum);
    if (!Number.isInteger(expected) || expected < 0 || expected > 0xffffffff || expected !== crc32c(bytes)) throw new Error();
    return bytes;
  } catch {
    bytes?.fill(0);
    throw new Error('KMS response integrity verification failed.');
  }
}

async function kmsRequest(http: HttpClient, accessToken: string, keyName: string, operation: 'encrypt' | 'decrypt',
  data: Buffer, aad: Buffer): Promise<Record<string, unknown>> {
  assertKeyName(keyName);
  if (typeof accessToken !== 'string' || accessToken.length > 12 * 1024 || !/^[A-Za-z0-9._~+\/-]+=*$/.test(accessToken)) {
    throw new Error('The box KMS access token is invalid.');
  }
  if (!Buffer.isBuffer(data) || !Buffer.isBuffer(aad) || data.length > (operation === 'encrypt' ? 64 : 128) * 1024 || aad.length > 64 * 1024) {
    throw new Error('The box KMS request exceeds the supported key or authenticated data size.');
  }
  const field = operation === 'encrypt' ? 'plaintext' : 'ciphertext';
  let response: HttpResponse;
  try {
    response = await http.request({
      method: 'POST', url: `https://cloudkms.googleapis.com/v1/${keyName}:${operation}`,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ [field]: data.toString('base64'), additionalAuthenticatedData: aad.toString('base64'),
        [`${field}Crc32c`]: String(crc32c(data)), additionalAuthenticatedDataCrc32c: String(crc32c(aad)) }),
    });
  } catch { throw new Error('Could not reach KMS for the box key. Check the connection and key-release policy.'); }
  if (response.status < 200 || response.status >= 300) {
    throw new Error('KMS refused the box key operation. Check the key name and key-release policy.');
  }
  try {
    const body = response.json<unknown>();
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
    return body as Record<string, unknown>;
  } catch { throw new Error('KMS returned an invalid response.'); }
}

export async function kmsEncrypt(http: HttpClient, accessToken: string, keyName: string, data: Buffer, aad: Buffer): Promise<Buffer> {
  const body = await kmsRequest(http, accessToken, keyName, 'encrypt', data, aad);
  if (body.verifiedPlaintextCrc32c !== true || body.verifiedAdditionalAuthenticatedDataCrc32c !== true) {
    throw new Error('KMS request integrity verification failed.');
  }
  const ciphertext = checkedBytes(body.ciphertext, body.ciphertextCrc32c);
  if (ciphertext.length === 0) throw new Error('KMS response integrity verification failed.');
  return ciphertext;
}

export async function kmsDecrypt(http: HttpClient, accessToken: string, keyName: string, data: Buffer, aad: Buffer): Promise<Buffer> {
  const body = await kmsRequest(http, accessToken, keyName, 'decrypt', data, aad);
  return checkedBytes(body.plaintext, body.plaintextCrc32c);
}
