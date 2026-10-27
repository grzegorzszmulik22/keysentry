// Canonical JSON: the exact bytes that get hashed and signed (audit chain, checkpoints, release manifests).

/** Keys sorted at every depth, no whitespace, `undefined` object members dropped, non-finite numbers rejected. */
export function canonicalJson(value: unknown): string {
  return encode(value, '$');
}

function encode(value: unknown, path: string): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError(`canonicalJson: non-finite number at ${path}`);
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((v, i) => (v === undefined ? 'null' : encode(v, `${path}[${i}]`))).join(',')}]`;
      }
      const obj = value as Record<string, unknown>;
      const parts: string[] = [];
      for (const key of Object.keys(obj).sort()) {
        const v = obj[key];
        if (v === undefined) continue;
        parts.push(`${JSON.stringify(key)}:${encode(v, `${path}.${key}`)}`);
      }
      return `{${parts.join(',')}}`;
    }
    default:
      throw new TypeError(`canonicalJson: unsupported ${typeof value} at ${path}`);
  }
}
