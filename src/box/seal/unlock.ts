import { hkdfSync } from 'node:crypto';

export function assertDeviceShare(share: Buffer): void {
  if (!Buffer.isBuffer(share) || share.length !== 32) throw new Error('The box device share must be exactly 32 bytes.');
}

/** Share B is HKDF info, not persisted alongside the KMS-wrapped share A. */
export function deriveUnlockDataKey(shareA: Buffer, boxId: string, shareB: Buffer): Buffer {
  if (!Buffer.isBuffer(shareA) || shareA.length !== 32) throw new Error('The box KMS share must be exactly 32 bytes.');
  assertDeviceShare(shareB);
  if (typeof boxId !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(boxId)) throw new Error('The box id is invalid.');
  return Buffer.from(hkdfSync('sha256', shareA, Buffer.from(boxId, 'utf8'), shareB, 32));
}
