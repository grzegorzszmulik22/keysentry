import { createRedactor } from '../../core/redact.js';
import type { NotifyChannel, Redactor } from '../../types.js';
import { assertSafeMessage, assertSafeText, NotifyDeliveryError } from '../message.js';
import { renderPlain } from '../render.js';

export function createConsoleChannel(write: (line: string) => unknown, deps?: { redactor: Redactor }): NotifyChannel {
  const redactor = deps?.redactor ?? createRedactor();
  return { id: 'console', kind: 'console', async send(m) {
    assertSafeMessage(m, redactor);
    const text = renderPlain(m);
    assertSafeText(text, redactor);
    try { await write(text); } catch { throw new NotifyDeliveryError('console'); }
  } };
}
