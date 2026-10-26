import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { ProviderId, RotationMethod } from '../../src/types.js';
import { getProvider, PROVIDER_CREDENTIALS } from '../../src/providers/index.js';

const providers: [ProviderId, RotationMethod][] = [
  ['openai', 'auto'], ['anthropic', 'guided'], ['openrouter', 'auto'], ['stripe', 'guided'],
  ['resend', 'auto'], ['cloudflare', 'atomic-roll'], ['github', 'guided'], ['aws', 'auto'],
  ['supabase', 'guided'], ['database', 'guided'], ['slack', 'guided'], ['sendgrid', 'guided'],
  ['twilio', 'guided'], ['google', 'guided'], ['private-key', 'guided'], ['crypto-wallet', 'guided'],
  ['app-secret', 'generate'], ['encryption-key', 'guided'], ['unknown', 'guided'],
];

describe('provider registry', () => {
  it.each(providers)('resolves %s with the required rotation capability', (id, method) => {
    const adapter = getProvider(id);
    expect(adapter.id).toBe(id);
    expect(adapter.method).toBe(method);
    expect(typeof adapter.verify).toBe('function');
    expect(adapter.guidance().steps.length).toBeGreaterThan(0);
    expect(adapter.guidance().url.startsWith('https://')).toBe(true);
    if (method !== 'guided') expect(typeof adapter.rotate).toBe('function');
    if (method === 'auto') expect(typeof adapter.revoke).toBe('function');
  });

  it('exposes every management credential consumed by adapters', () => {
    expect(PROVIDER_CREDENTIALS).toEqual({
      openai: ['OPENAI_ADMIN_KEY'], anthropic: ['ANTHROPIC_ADMIN_KEY'],
      openrouter: ['OPENROUTER_PROVISIONING_KEY'], stripe: [], resend: ['RESEND_ADMIN_KEY'],
      cloudflare: ['CLOUDFLARE_ADMIN_TOKEN'], github: [], aws: [], supabase: [], database: [],
      slack: [], sendgrid: [], twilio: [], google: [], 'private-key': [], 'crypto-wallet': [],
      'app-secret': [], 'encryption-key': [], unknown: [],
    });
  });

  it('requires data migration before replacing an encryption key', () => {
    const adapter = getProvider('encryption-key');
    expect(adapter.rotate).toBeUndefined();
    expect(adapter.guidance().steps[0]).toBe('Replacing a data-encryption key requires re-encrypting existing data first; never swap the variable on its own.');
  });

  it('rejects unsupported runtime input without echoing it', () => {
    const input = randomBytes(32).toString('hex');
    try { getProvider(input as ProviderId); }
    catch (error) {
      expect(String(error).includes(input)).toBe(false);
      expect(String(error)).toContain('Unsupported provider');
      return;
    }
    throw new Error('Expected unsupported provider rejection');
  });
});
