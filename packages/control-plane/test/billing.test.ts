import { createHmac } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { createBilling } from '../src/billing.js';

const secret = 'whsec_local_emulator_only';
const now = 1_792_137_600_000;
function signature(raw: Buffer, t = Math.floor(now / 1000)) {
  return `t=${t},v1=${createHmac('sha256', secret).update(`${t}.`).update(raw).digest('hex')}`;
}
function setup() {
  const data = new Map<string, unknown>();
  const storage = {
    async get<T>(key: string): Promise<T | null> { return structuredClone(data.get(key) as T ?? null); },
    async put(key: string, value: unknown) { data.set(key, structuredClone(value)); },
    async delete(key: string) { data.delete(key); },
    async list(prefix: string) { return [...data.keys()].filter(key => key.startsWith(prefix)); },
  };
  const account: { id: string; plan: 'free' | 'paid'; customerId?: string; subscriptionId?: string } = { id: 'account-one', plan: 'free' };
  const accounts = {
    async get(id: string) { return id === account.id ? structuredClone(account) : null; },
    async setPlan(id: string, plan: 'free' | 'paid', billing?: { customerId?: string; subscriptionId?: string }) {
      if (id !== account.id) throw new Error('missing');
      Object.assign(account, { plan }, billing);
    },
  };
  const billing = createBilling({ storage, accounts, endpointSecret: secret, now: () => now });
  return { billing, account, storage, accounts };
}
function checkout(id = 'evt-one', accountId = 'account-one') {
  return Buffer.from(JSON.stringify({ id, type: 'checkout.session.completed', data: { object: { client_reference_id: accountId, customer: 'cus-one', subscription: 'sub-one' } } }));
}

describe('Stripe billing hooks', () => {
  test('a verified checkout marks the account paid and deletion marks it free', async () => {
    const ctx = setup(); const raw = checkout();
    expect(await ctx.billing.handle(raw, signature(raw))).toEqual({ received: true, applied: true, replayed: false });
    expect(ctx.account.plan).toBe('paid');
    const deleted = Buffer.from(JSON.stringify({ id: 'evt-deleted', type: 'customer.subscription.deleted', data: { object: { id: 'sub-one', customer: 'cus-one' } } }));
    await ctx.billing.handle(deleted, signature(deleted));
    expect(ctx.account.plan).toBe('free');
  });
  test('signature verification uses exact bytes rather than parsed JSON', async () => {
    const ctx = setup(); const raw = checkout();
    await expect(ctx.billing.handle(Buffer.from(`${raw.toString()} `), signature(raw))).rejects.toThrow();
    expect(ctx.account.plan).toBe('free');
  });
  test.each(['t=1792137600,v1=00', 't=1792137600,v1=xx', 'v1=abcd', 't=1792137600,t=1792137600,v1=00'])('invalid header %s is refused', async (header) => {
    const ctx = setup(); await expect(ctx.billing.handle(checkout(), header)).rejects.toThrow(); expect(ctx.account.plan).toBe('free');
  });
  test.each([-301, 301])('a timestamp offset %i seconds is refused', async (offset) => {
    const ctx = setup(); const raw = checkout(); await expect(ctx.billing.handle(raw, signature(raw, Math.floor(now / 1000) + offset))).rejects.toThrow();
  });
  test('any matching v1 signature is accepted during rotation', async () => {
    const ctx = setup(); const raw = checkout(); const valid = signature(raw);
    await ctx.billing.handle(raw, `${valid.split(',')[0]},v1=${'00'.repeat(32)},${valid.split(',')[1]}`);
    expect(ctx.account.plan).toBe('paid');
  });
  test.each([-300, 300])('the tolerance boundary %i seconds is accepted', async (offset) => {
    const ctx = setup(); const raw = checkout(); await ctx.billing.handle(raw, signature(raw, Math.floor(now / 1000) + offset));
    expect(ctx.account.plan).toBe('paid');
  });
  test('concurrent duplicate events apply only once', async () => {
    const ctx = setup(); const raw = checkout();
    const results = await Promise.all([ctx.billing.handle(raw, signature(raw)), ctx.billing.handle(raw, signature(raw))]);
    expect(results.filter(result => result.applied)).toHaveLength(1);
    expect(results.filter(result => result.replayed)).toHaveLength(1);
  });
  test('replayed event IDs are ignored even by a recreated billing service', async () => {
    const ctx = setup(); const raw = checkout(); await ctx.billing.handle(raw, signature(raw)); ctx.account.plan = 'free';
    const other = createBilling({ storage: ctx.storage, accounts: ctx.accounts, endpointSecret: secret, now: () => now });
    expect(await other.handle(raw, signature(raw))).toEqual({ received: true, applied: false, replayed: true }); expect(ctx.account.plan).toBe('free');
  });
  test('unknown events and unknown account references are acknowledged without changing plans', async () => {
    const ctx = setup();
    for (const raw of [Buffer.from('{"id":"evt-unknown","type":"other","data":{"object":{}}}'), checkout('evt-missing', 'missing')]) {
      expect(await ctx.billing.handle(raw, signature(raw))).toEqual({ received: true, applied: false, replayed: false });
    }
    expect(ctx.account.plan).toBe('free');
  });
  test('checkout metadata may identify an account but an old subscription cannot cancel a new one', async () => {
    const ctx = setup(); const raw = Buffer.from(JSON.stringify({ id: 'evt-meta', type: 'checkout.session.completed', data: { object: { metadata: { accountId: 'account-one' }, customer: 'cus-one', subscription: 'sub-new' } } }));
    await ctx.billing.handle(raw, signature(raw));
    const deleted = Buffer.from(JSON.stringify({ id: 'evt-old', type: 'customer.subscription.deleted', data: { object: { id: 'sub-old', customer: 'cus-one' } } }));
    await ctx.billing.handle(deleted, signature(deleted)); expect(ctx.account.plan).toBe('paid');
  });
});
