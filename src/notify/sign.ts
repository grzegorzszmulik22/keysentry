import { createHash } from 'node:crypto';
import { canonicalJson, signDetached, verifyDetached } from '../security/index.js';
import type { DeviceKey } from '../security/index.js';
import type { NotifyMessage, SignedNotifyMessage } from '../types.js';

export const NOTIFY_PREFIX = 'keysentry-notify:v1\n';
const MESSAGE_FIELDS = ['id', 'at', 'kind', 'severity', 'title', 'lines', 'actionId', 'approveUrl'] as const;
const REQUIRED_TEXT = ['id', 'at', 'kind', 'title'] as const;

/** Validate data properties before reading an untrusted signed message. */
function messageData(value: unknown, signed: boolean): { message: NotifyMessage; fields: PropertyDescriptorMap } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error();
  const fields = Object.getOwnPropertyDescriptors(value);
  const permitted: readonly string[] = signed ? [...MESSAGE_FIELDS, 'keyId', 'sig', 'code'] : MESSAGE_FIELDS;
  if (Reflect.ownKeys(value).some((key) => typeof key !== 'string' || !permitted.includes(key))) throw new Error();
  if (Object.values(fields).some((field) => !('value' in field))) throw new Error();
  const data = Object.fromEntries(Object.entries(fields).map(([key, field]) => [key, field.value])) as Record<string, unknown>;
  if (REQUIRED_TEXT.some((key) => typeof data[key] !== 'string')) throw new Error();
  if (!['info', 'warning', 'urgent'].includes(data.severity as string)) throw new Error();
  if (!Array.isArray(data.lines)) throw new Error();
  if (Object.getPrototypeOf(data.lines) !== Array.prototype) throw new Error();
  const lineDescriptors: Record<string, PropertyDescriptor> = Object.getOwnPropertyDescriptors(data.lines);
  if (Object.values(lineDescriptors).some((field) => !('value' in field))) throw new Error();
  const lineCount = lineDescriptors.length?.value as number;
  if (Reflect.ownKeys(data.lines).length !== lineCount + 1) throw new Error();
  const lines: string[] = [];
  for (let index = 0; index < lineCount; index += 1) {
    const line = lineDescriptors[String(index)]?.value as unknown;
    if (typeof line !== 'string') throw new Error();
    lines.push(line);
  }
  for (const key of ['actionId', 'approveUrl']) {
    if (data[key] !== undefined && typeof data[key] !== 'string') throw new Error();
  }
  const message: NotifyMessage = {
    id: data.id as string, at: data.at as string, kind: data.kind as string,
    severity: data.severity as NotifyMessage['severity'], title: data.title as string, lines,
  };
  if (data.actionId !== undefined) message.actionId = data.actionId as string;
  if (data.approveUrl !== undefined) message.approveUrl = data.approveUrl as string;
  return { message, fields };
}

function codeOf(signature: Buffer): string {
  const hash = createHash('sha256').update(signature).digest();
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let accumulator = 0;
  let result = '';
  for (const byte of hash.subarray(0, 5)) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet[(accumulator >>> bits) & 31];
    }
  }
  return result.slice(0, 4) + '-' + result.slice(4, 8);
}

export function signMessage(m: NotifyMessage, key: DeviceKey): SignedNotifyMessage {
  let message: NotifyMessage;
  try {
    message = messageData(m, false).message;
  } catch {
    throw new TypeError('Invalid notification message');
  }
  try {
    const keyId = createHash('sha256').update(key.publicKeyDer).digest('hex').slice(0, 16);
    if (keyId !== key.keyId) throw new Error();
    const signature = signDetached(key.privateKeyDer, Buffer.from(NOTIFY_PREFIX + canonicalJson(message)));
    if (!verifyDetached(key.publicKeyDer, Buffer.from(NOTIFY_PREFIX + canonicalJson(message)), signature)) throw new Error();
    return { ...message, keyId, sig: signature.toString('base64'), code: codeOf(signature) };
  } catch {
    throw new Error('Unable to sign notification');
  }
}

/** Invalid, edited or malformed messages return false without reflecting input. */
export function verifyMessage(m: SignedNotifyMessage, publicKeyDer: Buffer): boolean {
  try {
    const { message, fields } = messageData(m, true);
    const keyId = fields.keyId?.value as unknown;
    const sig = fields.sig?.value as unknown;
    const code = fields.code?.value as unknown;
    if (typeof keyId !== 'string' || keyId !== createHash('sha256').update(publicKeyDer).digest('hex').slice(0, 16)) return false;
    if (typeof sig !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(sig)) return false;
    const signature = Buffer.from(sig, 'base64');
    if (signature.length !== 64 || signature.toString('base64') !== sig || code !== codeOf(signature)) return false;
    return verifyDetached(publicKeyDer, Buffer.from(NOTIFY_PREFIX + canonicalJson(message)), signature);
  } catch {
    return false;
  }
}
