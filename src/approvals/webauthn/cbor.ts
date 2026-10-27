import { isUtf8 } from 'node:buffer';

const MAX_BYTES = 64 * 1024;
const MAX_DEPTH = 16;
const MAX_ITEMS = 1024;
const MAX_SAFE_ARGUMENT = BigInt(Number.MAX_SAFE_INTEGER);

interface CborOptions {
  maxDepth?: number;
  maxItems?: number;
}

/** A fixed message keeps untrusted CBOR content out of error reporting. */
export class CborError extends Error {
  constructor() {
    super('CBOR data is invalid or exceeds its limits.');
    this.name = 'CborError';
  }
}

function limit(value: number | undefined, cap: number, minimum: number): number {
  if (value === undefined) return cap;
  if (!Number.isInteger(value) || value < minimum || value > cap) throw new CborError();
  return value;
}

class Decoder {
  offset = 0;
  private items = 0;

  constructor(
    private readonly bytes: Buffer,
    private readonly maxDepth: number,
    private readonly maxItems: number,
  ) {}

  private requireBytes(length: number): void {
    if (length > this.bytes.length - this.offset) throw new CborError();
  }

  private argument(additional: number): number {
    if (additional < 24) return additional;
    const length = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (length === 0) throw new CborError();
    this.requireBytes(length);
    let value: number;
    if (length === 8) {
      const wide = this.bytes.readBigUInt64BE(this.offset);
      if (wide < 0x1_0000_0000n || wide > MAX_SAFE_ARGUMENT) throw new CborError();
      value = Number(wide);
    } else {
      value = this.bytes.readUIntBE(this.offset, length);
      const minimum = length === 1 ? 24 : length === 2 ? 256 : 65_536;
      if (value < minimum) throw new CborError();
    }
    this.offset += length;
    return value;
  }

  /** The root is depth zero; each decoded value, including a key, consumes one item. */
  read(depth: number): unknown {
    if (depth > this.maxDepth || this.items >= this.maxItems) throw new CborError();
    this.items++;
    this.requireBytes(1);
    const initial = this.bytes[this.offset++]!;
    const major = initial >>> 5;
    const additional = initial & 0x1f;

    if (major === 7) {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      throw new CborError();
    }
    if (major === 6) throw new CborError();
    const argument = this.argument(additional);
    if (major === 0) return argument;
    if (major === 1) {
      const value = -1 - argument;
      if (!Number.isSafeInteger(value)) throw new CborError();
      return value;
    }

    if (major === 2 || major === 3) {
      this.requireBytes(argument);
      const bytes = this.bytes.subarray(this.offset, this.offset + argument);
      this.offset += argument;
      if (major === 2) return Buffer.from(bytes);
      if (!isUtf8(bytes)) throw new CborError();
      return bytes.toString('utf8');
    }

    const remainingItems = this.maxItems - this.items;
    if (major === 4) {
      // Every child needs at least one item and one byte, before any array is allocated.
      if (argument > remainingItems) throw new CborError();
      this.requireBytes(argument);
      const values: unknown[] = [];
      for (let i = 0; i < argument; i++) values.push(this.read(depth + 1));
      return values;
    }

    // Map keys and values each need at least one item and one byte.
    if (argument > Math.floor(remainingItems / 2)) throw new CborError();
    this.requireBytes(argument * 2);
    const values = new Map<number | string, unknown>();
    for (let i = 0; i < argument; i++) {
      const key = this.read(depth + 1);
      if ((typeof key !== 'number' && typeof key !== 'string') || values.has(key)) throw new CborError();
      values.set(key, this.read(depth + 1));
    }
    return values;
  }
}

/** Decode one definite-length CBOR value and reject any following bytes. */
export function decodeCbor(bytes: Buffer, opts?: CborOptions): unknown {
  const { value, bytesRead } = decodeCborFirst(bytes, opts);
  if (bytesRead !== bytes.length) throw new CborError();
  return value;
}

/** Internal integration helper for a COSE key followed by authenticator extensions. */
export function decodeCborFirst(bytes: Buffer, opts?: CborOptions): { value: unknown; bytesRead: number } {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_BYTES) throw new CborError();
  const decoder = new Decoder(bytes, limit(opts?.maxDepth, MAX_DEPTH, 0), limit(opts?.maxItems, MAX_ITEMS, 1));
  const value = decoder.read(0);
  return { value, bytesRead: decoder.offset };
}
