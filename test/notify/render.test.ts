import { describe, expect, test } from 'vitest';
import type { SignedNotifyMessage } from '../../src/types.js';
import { renderLimited, renderPlain } from '../../src/notify/render.js';

const message: SignedNotifyMessage = {
  id: 'm-1', at: '2026-10-27T10:00:00Z', kind: 'test', severity: 'info', title: 'Ready to rotate',
  lines: ['Two services are ready.', 'The old key stays until checks pass.'],
  approveUrl: 'https://localhost/approve/a-1', keyId: '0123456789abcdef', sig: 'signature', code: 'ABCD-2345',
};
const html = (text: string) => text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

describe('notification rendering', () => {
  test('uses one plain renderer for title, lines, approval link and verification code', () => {
    expect(renderPlain(message)).toBe('Ready to rotate\n\nTwo services are ready.\nThe old key stays until checks pass.\n\nApprove: https://localhost/approve/a-1\n\nVerification code: ABCD-2345');
    expect(renderLimited(message, { limit: 4096 })).toBe(renderPlain(message));
    expect(renderPlain({ ...message, lines: [], approveUrl: undefined })).toBe('Ready to rotate\n\nVerification code: ABCD-2345');
  });

  test.each([2000, 4000, 4096])('caps escaped text at %i characters without cutting its footer or entities', (limit) => {
    const rendered = renderLimited({ ...message, title: '<&>'.repeat(3000), lines: ['&'.repeat(10000)] }, { limit, escape: html });
    expect(rendered.length).toBeLessThanOrEqual(limit);
    expect(rendered).toContain('Verification code: ABCD-2345');
    expect(rendered.endsWith('… (shortened)')).toBe(true);
    expect(rendered).not.toMatch(/&(?!amp;|lt;|gt;)/);
    expect(rendered).not.toContain('<');
  });

  test('caps ntfy text in UTF-8 bytes while preserving whole emoji and the code', () => {
    const rendered = renderLimited({ ...message, title: '🔑'.repeat(4000), lines: ['é'.repeat(5000)] }, { limit: 4096, bytes: true });
    expect(Buffer.byteLength(rendered)).toBeLessThanOrEqual(4096);
    expect(rendered).toContain('Verification code: ABCD-2345');
    expect(rendered.endsWith('… (shortened)')).toBe(true);
    expect(Buffer.from(rendered).toString('utf8')).toBe(rendered);
    expect(rendered).not.toContain('\ufffd');
  });

  test('preserves the exact limit and rejects a budget too small for the verification footer', () => {
    const plain = renderPlain(message);
    expect(renderLimited(message, { limit: plain.length })).toBe(plain);
    expect(() => renderLimited(message, { limit: 10 })).toThrow('Notification limit is too small');
    expect(() => renderLimited(message, { limit: Number.NaN })).toThrow('Invalid notification limit');
  });
});
