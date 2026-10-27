import type { SignedNotifyMessage } from '../types.js';

function body(m: SignedNotifyMessage): string {
  const sections = [m.title];
  if (m.lines.length) sections.push(m.lines.join('\n'));
  if (m.approveUrl) sections.push(`Approve: ${m.approveUrl}`);
  return sections.join('\n\n');
}

function footer(m: SignedNotifyMessage): string {
  return `Verification code: ${m.code}`;
}

export function renderPlain(m: SignedNotifyMessage): string {
  return `${body(m)}\n\n${footer(m)}`;
}

/** Truncate before escaping, at a code-point boundary, while budgeting the escaped output. */
export function renderLimited(
  m: SignedNotifyMessage,
  opts: { limit: number; bytes?: boolean; escape?: (text: string) => string },
): string {
  if (!Number.isSafeInteger(opts.limit) || opts.limit < 1) throw new TypeError('Invalid notification limit');
  const escape = opts.escape ?? ((text: string) => text);
  const size = opts.bytes ? (text: string) => Buffer.byteLength(text, 'utf8') : (text: string) => text.length;
  const full = escape(renderPlain(m));
  if (size(full) <= opts.limit) return full;
  const suffix = escape(`\n\n${footer(m)}\n… (shortened)`);
  if (size(suffix) > opts.limit) throw new RangeError('Notification limit is too small');
  const characters = Array.from(body(m));
  let low = 0;
  let high = characters.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (size(escape(characters.slice(0, middle).join('')) + suffix) <= opts.limit) low = middle;
    else high = middle - 1;
  }
  return escape(characters.slice(0, low).join('')) + suffix;
}
