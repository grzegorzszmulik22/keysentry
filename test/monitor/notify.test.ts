import { describe, expect, it } from 'vitest';
import { combineNotifiers, createConsoleNotifier, createWebhookNotifier } from '../../src/monitor/notify.js';
import { FakeHttp, json } from '../helpers/fake-http.js';

describe('monitor notifiers', () => {
  it('posts both Slack and Discord fields without plaintext keys or arbitrary evidence', async () => {
    const http = new FakeHttp().on('POST', /^https:\/\/example\.invalid\/hook$/, () => json(200, {}));
    const notifier = createWebhookNotifier('https://example.invalid/hook', http);
    const secret = `sk-or-v1-${'a'.repeat(64)}`;
    await notifier.notify('Leak detected', `Key ${secret} needs attention.`, {
      id: 's', kind: 'leak_detected', at: '2026-10-26T12:00:00Z', confidence: 'high', clusterIds: [], summary: 'Leak', evidence: { secret: 'custom-unknown-secret-value' },
    });
    expect(http.calls).toHaveLength(1);
    const body = JSON.parse(http.calls[0]!.body!);
    expect(body.text).toBe(body.content);
    expect(body.text).toContain('Leak detected');
    expect(http.calls[0]!.body).not.toContain(secret);
    expect(http.calls[0]!.body).not.toContain('custom-unknown-secret-value');
  });

  it('redacts console notifications before passing them to the logger', async () => {
    const messages: string[] = [];
    const log = { info: (message: string) => { messages.push(message); }, warn() {}, error() {}, debug() {} };
    const secret = `sk-or-v1-${'b'.repeat(64)}`;
    await createConsoleNotifier(log).notify(`Detected ${secret}`, 'Attention required');
    expect(messages.join('\n')).toContain('Attention required');
    expect(messages.join('\n')).not.toContain(secret);
  });

  it('uses generic webhook errors and still attempts other combined notifiers', async () => {
    const http = new FakeHttp().on('POST', /hook/, () => json(500, { error: 'sensitive body' }));
    const received: string[] = [];
    const notifier = combineNotifiers(createWebhookNotifier('https://example.invalid/hook', http), {
      async notify(title) { received.push(title); },
    });
    await expect(notifier.notify('Alert', 'Body')).rejects.toThrow('notification');
    expect(received).toEqual(['Alert']);
  });
});
