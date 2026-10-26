import type { Logger, Redactor } from '../types.js';
import { secretPatternRanges } from './classify.js';

const MASK = '«redacted»';

export function createRedactor(): Redactor {
  const secrets = new Set<string>();
  return {
    register(secret) {
      if (secret.length < 6 || secrets.has(secret)) return;
      secrets.add(secret);
    },
    redact(text) {
      // Match against the original text, then merge overlaps. Replacing first
      // could hide part of a longer pattern or a partially overlapping value.
      const ranges = secretPatternRanges(text);
      for (const secret of secrets) {
        let index = text.indexOf(secret);
        while (index >= 0) {
          ranges.push([index, index + secret.length]);
          index = text.indexOf(secret, index + 1);
        }
      }
      const merged: [number, number][] = [];
      for (const [start, end] of ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1])) {
        const previous = merged.at(-1);
        if (previous && start < previous[1]) previous[1] = Math.max(previous[1], end);
        else merged.push([start, end]);
      }
      let output = '';
      let cursor = 0;
      for (const [start, end] of merged) {
        output += text.slice(cursor, start) + MASK;
        cursor = end;
      }
      return output + text.slice(cursor);
    },
  };
}

type Level = 'debug' | 'info' | 'warn' | 'error';
const LEVELS: Record<Level, number> = { debug: 0, info: 1, warn: 2, error: 3 };

export function createLogger(opts: {
  redactor: Redactor;
  level?: Level;
  json?: boolean;
  sink?: (line: string) => void;
}): Logger {
  const minimum = LEVELS[opts.level ?? 'info'];
  const sink = opts.sink ?? ((line: string) => { process.stderr.write(`${line}\n`); });

  function safeData(value: unknown, ancestors = new Set<object>()): unknown {
    if (typeof value === 'string') return opts.redactor.redact(value);
    if (typeof value === 'function' || typeof value === 'symbol') return undefined;
    if (typeof value === 'bigint') return opts.redactor.redact(value.toString());
    if (typeof value === 'number') {
      const text = String(value);
      const redacted = opts.redactor.redact(text);
      return redacted === text ? value : redacted;
    }
    if (value === null || typeof value !== 'object') return value;
    if (ancestors.has(value)) return '[Circular]';
    ancestors.add(value);
    try {
      if (value instanceof Error) return { name: opts.redactor.redact(value.name), message: opts.redactor.redact(value.message) };
      if (Array.isArray(value)) {
        const array: unknown[] = [];
        for (let index = 0; index < value.length; index += 1) array.push(safeData(value[index], ancestors));
        return array;
      }
      if (value instanceof Date) {
        return Number.isNaN(Date.prototype.getTime.call(value)) ? null : opts.redactor.redact(Date.prototype.toISOString.call(value));
      }
      const object: Record<string, unknown> = Object.create(null);
      for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
        if (descriptor.enumerable) object[opts.redactor.redact(key)] = 'value' in descriptor ? safeData(descriptor.value, ancestors) : '[Getter]';
      }
      return object;
    } catch {
      return '[Unserializable]';
    } finally {
      ancestors.delete(value);
    }
  }

  function write(level: Level, message: string, data?: Record<string, unknown>): void {
    if (LEVELS[level] < minimum) return;
    const cleanMessage = opts.redactor.redact(message);
    const cleanData = data === undefined ? undefined : safeData(data);
    if (opts.json) {
      sink(JSON.stringify({ level, message: cleanMessage, ...(cleanData === undefined ? {} : { data: cleanData }) }));
    } else {
      sink(`[${level}] ${cleanMessage}${cleanData === undefined ? '' : ` ${JSON.stringify(cleanData)}`}`);
    }
  }

  return {
    debug: (message, data) => write('debug', message, data),
    info: (message, data) => write('info', message, data),
    warn: (message, data) => write('warn', message, data),
    error: (message, data) => write('error', message, data),
  };
}
