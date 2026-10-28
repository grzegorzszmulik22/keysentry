import { createHmac } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { json } from '../../../test/helpers/fake-http.js';
import type { HttpClient, HttpRequest } from '../../../src/types.js';
import { BillingUnavailableError, createBilling } from '../src/billing.js';

const secret = 'whsec_local_emulator_only';
const apiKey = 'rk_test_localonly0123';
const now = 1_792_137_600_000;
function signature(raw: Buffer, t = Math.floor(now / 1000)) {
  return `t=${t},v1=${createHmac('sha256', secret).update(`${t}.`).update(raw).digest('hex')}`;
}
interface Sub { id: string; customer: string; status: string; price?: string }
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
  const subscriptions = new Map<string, Sub>([['sub-one', { id: 'sub-one', customer: 'cus-one', status: 'active', price: 'price_plan' }]]);
  const calls: HttpRequest[] = [];
  let down = false;
  const http: HttpClient = { async request(req) {
    calls.push(req);
    if (down) return json(500, { error: { message: `planted upstream ${apiKey}` } });
    const id = /^https:\/\/api\.stripe\.com\/v1\/subscriptions\/([A-Za-z0-9_-]+)$/.exec(req.url)?.[1];
    const sub = id ? subscriptions.get(id) : undefined;
    if (!sub || req.headers?.authorization !== `Bearer ${apiKey}`) return json(404, {});
    return json(200, { id: sub.id, object: 'subscription', customer: sub.customer, status: sub.status,
      items: { object: 'list', has_more: false, data: [{ id: 'si_1', price: { id: sub.price ?? 'price_plan' } }] } });
  } };
  const billing = createBilling({ storage, accounts, endpointSecret: secret, priceId: 'price_plan', stripe: { http, apiKey }, now: () => now });
  return { billing, account, storage, accounts, subscriptions, calls, http, setDown(value: boolean) { down = value; } };
}
function event(id: string, type: string, object: Record<string, unknown>, created?: number) {
  return Buffer.from(JSON.stringify({ id, type, ...(created === undefined ? {} : { created }), data: { object } }));
}
const session = (extra: Record<string, unknown> = {}) => ({ object: 'checkout.session', id: 'cs_test_one', mode: 'subscription', status: 'complete',
  payment_status: 'paid', client_reference_id: 'account-one', customer: 'cus-one', subscription: 'sub-one', ...extra });
function checkout(id = 'evt-one', extra: Record<string, unknown> = {}, type = 'checkout.session.completed') {
  return event(id, type, session(extra), 1_792_137_000);
}
async function deliver(ctx: ReturnType<typeof setup>, raw: Buffer) { return ctx.billing.handle(raw, signature(raw)); }

describe('Stripe billing hooks', () => {
  test('a verified paid checkout to the configured price marks the account paid and deletion marks it free', async () => {
    const ctx = setup();
    expect(await deliver(ctx, checkout())).toEqual({ received: true, applied: true, replayed: false });
    expect(ctx.account).toMatchObject({ plan: 'paid', customerId: 'cus-one', subscriptionId: 'sub-one' });
    expect(ctx.calls.map(call => call.url)).toEqual(['https://api.stripe.com/v1/subscriptions/sub-one']);
    await deliver(ctx, event('evt-deleted', 'customer.subscription.deleted', { id: 'sub-one', customer: 'cus-one', status: 'canceled' }, 1_792_137_100));
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
    const results = await Promise.all([deliver(ctx, raw), deliver(ctx, raw)]);
    expect(results.filter(result => result.applied)).toHaveLength(1);
    expect(results.filter(result => result.replayed)).toHaveLength(1);
  });
  test('replayed event IDs are ignored even by a recreated billing service', async () => {
    const ctx = setup(); const raw = checkout(); await deliver(ctx, raw); ctx.account.plan = 'free';
    const other = createBilling({ storage: ctx.storage, accounts: ctx.accounts, endpointSecret: secret, priceId: 'price_plan', stripe: { http: ctx.http, apiKey }, now: () => now });
    expect(await other.handle(raw, signature(raw))).toEqual({ received: true, applied: false, replayed: true }); expect(ctx.account.plan).toBe('free');
  });
  test('unknown events and unknown account references are acknowledged without changing plans', async () => {
    const ctx = setup();
    for (const raw of [Buffer.from('{"id":"evt-unknown","type":"other","data":{"object":{}}}'), checkout('evt-missing', { client_reference_id: 'missing' })]) {
      expect(await deliver(ctx, raw)).toEqual({ received: true, applied: false, replayed: false });
    }
    expect(ctx.account.plan).toBe('free');
  });
  test('checkout metadata may identify an account but an old subscription cannot cancel a new one', async () => {
    const ctx = setup();
    ctx.subscriptions.set('sub-new', { id: 'sub-new', customer: 'cus-one', status: 'active' });
    await deliver(ctx, checkout('evt-meta', { client_reference_id: null, metadata: { accountId: 'account-one' }, subscription: 'sub-new' }));
    expect(ctx.account.plan).toBe('paid');
    await deliver(ctx, event('evt-old', 'customer.subscription.deleted', { id: 'sub-old', customer: 'cus-one' }, 1_792_137_100));
    expect(ctx.account.plan).toBe('paid');
  });
  test('the configuration must name a price and Stripe access', () => {
    const ctx = setup();
    const base = { storage: ctx.storage, accounts: ctx.accounts, endpointSecret: secret, stripe: { http: ctx.http, apiKey } };
    expect(() => createBilling({ ...base, priceId: '' })).toThrow('Billing price is required');
    expect(() => createBilling({ ...base, priceId: 'price_plan', stripe: { http: ctx.http, apiKey: 'not-a-key' } })).toThrow('Billing Stripe access is required');
  });
});

describe('M3: only a paid subscription to the configured price grants the plan', () => {
  test.each([
    ['payment_status unpaid (delayed payment method)', { payment_status: 'unpaid' }],
    ['one-time payment mode', { mode: 'payment', subscription: null }],
    ['an open session', { status: 'open' }],
    ['no subscription', { subscription: null }],
  ])('a completed checkout with %s grants nothing and asks Stripe nothing', async (_name, change) => {
    const ctx = setup();
    expect(await deliver(ctx, checkout('evt-x', change))).toMatchObject({ applied: false });
    expect(ctx.account.plan).toBe('free');
    expect(ctx.calls).toEqual([]);
  });
  test('no_payment_required (a trial) grants when Stripe reports the subscription trialing', async () => {
    const ctx = setup(); ctx.subscriptions.get('sub-one')!.status = 'trialing';
    await deliver(ctx, checkout('evt-trial', { payment_status: 'no_payment_required' }));
    expect(ctx.account.plan).toBe('paid');
  });
  test.each([
    ['another price', { price: 'price_other' }], ['another customer', { customer: 'cus-other' }], ['an incomplete subscription', { status: 'incomplete' }],
    ['a canceled subscription', { status: 'canceled' }],
  ])('a paid checkout for %s grants nothing', async (_name, change) => {
    const ctx = setup(); Object.assign(ctx.subscriptions.get('sub-one')!, change);
    expect(await deliver(ctx, checkout())).toMatchObject({ applied: false });
    expect(ctx.account.plan).toBe('free');
  });
  test('when Stripe cannot be reached the event fails retryably, records nothing, and is applied on retry', async () => {
    const ctx = setup(); ctx.setDown(true);
    const raw = checkout();
    const error = await deliver(ctx, raw).catch(e => e as Error);
    expect(error).toBeInstanceOf(BillingUnavailableError);
    expect((error as BillingUnavailableError).status).toBe(503);
    expect(JSON.stringify([(error as Error).message, (error as Error).stack])).not.toContain(apiKey);
    expect(await ctx.storage.list('stripe-events/')).toEqual([]);
    expect(ctx.account.plan).toBe('free');
    ctx.setDown(false);
    expect(await deliver(ctx, raw)).toMatchObject({ applied: true, replayed: false });
    expect(ctx.account.plan).toBe('paid');
  });
  test('a delayed payment is granted on async_payment_succeeded and revoked on async_payment_failed', async () => {
    const ctx = setup();
    await deliver(ctx, checkout('evt-pending', { payment_status: 'unpaid' }));
    expect(ctx.account.plan).toBe('free');
    await deliver(ctx, checkout('evt-succeeded', {}, 'checkout.session.async_payment_succeeded'));
    expect(ctx.account.plan).toBe('paid');
    await deliver(ctx, checkout('evt-failed', { payment_status: 'unpaid' }, 'checkout.session.async_payment_failed'));
    expect(ctx.account.plan).toBe('free');
  });
  test('async_payment_failed for another subscription leaves the current plan alone', async () => {
    const ctx = setup();
    await deliver(ctx, checkout());
    await deliver(ctx, checkout('evt-failed-other', { subscription: 'sub-other', payment_status: 'unpaid' }, 'checkout.session.async_payment_failed'));
    expect(ctx.account.plan).toBe('paid');
  });
});

describe('M3: subscription status updates', () => {
  const update = (id: string, status: string, created: number | undefined, price = 'price_plan') =>
    event(id, 'customer.subscription.updated', { id: 'sub-one', object: 'subscription', customer: 'cus-one', status,
      items: { object: 'list', has_more: false, data: [{ price: { id: price } }] } }, created);
  test.each(['unpaid', 'canceled', 'incomplete_expired', 'paused'])('%s revokes the paid plan', async status => {
    const ctx = setup(); await deliver(ctx, checkout());
    await deliver(ctx, update(`evt-${status}`, status, 1_792_137_100));
    expect(ctx.account.plan).toBe('free');
  });
  test('past_due keeps the plan while Stripe retries; active again after unpaid restores it', async () => {
    const ctx = setup(); await deliver(ctx, checkout());
    await deliver(ctx, update('evt-past-due', 'past_due', 1_792_137_100));
    expect(ctx.account.plan).toBe('paid');
    await deliver(ctx, update('evt-unpaid', 'unpaid', 1_792_137_200));
    expect(ctx.account.plan).toBe('free');
    await deliver(ctx, update('evt-active', 'active', 1_792_137_300));
    expect(ctx.account.plan).toBe('paid');
  });
  test('an older event delivered late does not undo a newer one', async () => {
    const ctx = setup(); await deliver(ctx, checkout());
    await deliver(ctx, update('evt-unpaid', 'unpaid', 1_792_137_300));
    await deliver(ctx, update('evt-stale-active', 'active', 1_792_137_200));
    expect(ctx.account.plan).toBe('free');
  });
  test('a switch to another price revokes, and a grant needs an orderable event', async () => {
    const ctx = setup(); await deliver(ctx, checkout());
    await deliver(ctx, update('evt-price', 'active', 1_792_137_100, 'price_other'));
    expect(ctx.account.plan).toBe('free');
    await deliver(ctx, update('evt-undated', 'active', undefined));
    expect(ctx.account.plan).toBe('free');
  });
  test('an update for a subscription the account no longer uses changes nothing', async () => {
    const ctx = setup(); await deliver(ctx, checkout());
    ctx.subscriptions.set('sub-two', { id: 'sub-two', customer: 'cus-one', status: 'active' });
    await deliver(ctx, checkout('evt-two', { subscription: 'sub-two' }));
    await deliver(ctx, update('evt-old-sub', 'canceled', 1_792_137_900));
    expect(ctx.account).toMatchObject({ plan: 'paid', subscriptionId: 'sub-two' });
  });
});
