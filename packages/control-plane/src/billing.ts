import { createHmac, timingSafeEqual } from 'node:crypto';
import type { HttpClient } from '../../../src/types.js';
import type { Storage } from './storage.js';

interface BillingAccount { id: string; plan: 'free' | 'paid'; customerId?: string; subscriptionId?: string }
export interface BillingOptions {
  storage: Storage;
  accounts: {
    get(accountId: string): Promise<BillingAccount | null>;
    setPlan(accountId: string, plan: 'free' | 'paid', billing?: { customerId?: string; subscriptionId?: string }): Promise<void>;
  };
  endpointSecret: string;
  /** The one Stripe price that buys the paid plan (`price_...`). */
  priceId: string;
  /**
   * Stripe API access used to confirm a completed checkout's subscription (status and price) before granting the
   * plan. `apiKey` should be a restricted key that can only read subscriptions; it never appears in errors or logs.
   */
  stripe: { http: HttpClient; apiKey: string };
  now?: () => number;
}
/** Thrown when Stripe could not confirm a payment; the webhook answers 503 so Stripe retries the event later. */
export class BillingUnavailableError extends Error {
  readonly status = 503;
  constructor() { super('Billing could not be confirmed. Stripe will retry.'); this.name = 'BillingUnavailableError'; }
}
interface SubscriptionRef { accountId: string; eventCreated?: number }

function fail(): never { throw new Error('Billing webhook could not be verified.'); }
function identifier(value: unknown): string | undefined { return typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value) ? value : undefined; }
function object(value: unknown): Record<string, unknown> | null { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null; }
function created(value: unknown): number | undefined { return Number.isSafeInteger(value) && (value as number) > 0 ? value as number : undefined; }

/**
 * Subscription statuses (https://docs.stripe.com/billing/subscriptions/overview#subscription-statuses):
 * `active` and `trialing` are entitled. `past_due` keeps the plan while Stripe retries the payment; Stripe's
 * failed-payment setting then moves it to `unpaid` or `canceled`, which revoke. `incomplete_expired` (first payment
 * never made) and `paused` (trial ended without a payment method) revoke. `incomplete` happens only before the
 * first payment, which the checkout itself confirms, so it changes nothing.
 */
const ENTITLED = new Set(['active', 'trialing', 'past_due']);
const REVOKED = new Set(['unpaid', 'canceled', 'incomplete_expired', 'paused']);
const GRANTING = new Set(['active', 'trialing']);

/** Verify the original request bytes, including whitespace, before JSON decoding. */
export function verifyStripeSignature(rawBody: Buffer, header: string, endpointSecret: string, now = Date.now()): void {
  if (!Buffer.isBuffer(rawBody) || rawBody.length > 256 * 1024 || typeof header !== 'string' || header.length > 4096 || !endpointSecret) fail();
  const fields = header.split(',').map(part => part.trim());
  const timestamps = fields.filter(part => part.startsWith('t=')).map(part => part.slice(2));
  if (timestamps.length !== 1 || !/^(0|[1-9][0-9]{0,15})$/.test(timestamps[0]!)) fail();
  const t = timestamps[0]!; const timestamp = Number(t);
  if (!Number.isSafeInteger(timestamp) || !Number.isFinite(now) || Math.abs(Math.floor(now / 1000) - timestamp) > 300) fail();
  const expected = createHmac('sha256', endpointSecret).update(`${t}.`).update(rawBody).digest();
  let valid = false;
  for (const field of fields) {
    if (!field.startsWith('v1=')) continue;
    const value = field.slice(3); if (!/^[a-fA-F0-9]{64}$/.test(value)) continue;
    valid = timingSafeEqual(Buffer.from(value, 'hex'), expected) || valid;
  }
  if (!valid) fail();
}

/** True when the subscription's items carry the configured price (and nothing hides further items). */
function hasPrice(subscription: Record<string, unknown>, priceId: string): boolean {
  const items = object(subscription.items);
  if (!items || items.has_more === true || !Array.isArray(items.data)) return false;
  return items.data.some(item => object(object(item)?.price)?.id === priceId);
}

/** Billing sees account references and plan identifiers, never provider credentials. */
export function createBilling(opts: BillingOptions) {
  if (!opts.endpointSecret) throw new Error('Billing endpoint secret is required.');
  if (typeof opts.priceId !== 'string' || !/^price_[A-Za-z0-9_]{1,120}$/.test(opts.priceId)) throw new Error('Billing price is required.');
  if (!opts.stripe || typeof opts.stripe.http?.request !== 'function' || typeof opts.stripe.apiKey !== 'string'
    || !/^(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,240}$/.test(opts.stripe.apiKey)) throw new Error('Billing Stripe access is required.');
  const now = opts.now ?? Date.now;
  let tail: Promise<unknown> = Promise.resolve();

  /** Current subscription from the Stripe API; any failure is a retryable 503, never a grant. */
  async function subscription(subscriptionId: string): Promise<Record<string, unknown>> {
    try {
      const response = await opts.stripe.http.request({ method: 'GET', url: `https://api.stripe.com/v1/subscriptions/${subscriptionId}`,
        headers: { authorization: `Bearer ${opts.stripe.apiKey}`, accept: 'application/json' } });
      if (response.status !== 200 || Buffer.byteLength(response.text) > 256 * 1024) throw new Error();
      const data = object(response.json<unknown>());
      if (!data || data.id !== subscriptionId) throw new Error();
      return data;
    } catch { throw new BillingUnavailableError(); }
  }
  async function ref(subscriptionId: string): Promise<SubscriptionRef | null> {
    const stored = await opts.storage.get<SubscriptionRef>(`stripe-subscriptions/${subscriptionId}`);
    return stored && typeof stored.accountId === 'string' ? stored : null;
  }
  async function remember(subscriptionId: string, accountId: string, at: number | undefined): Promise<void> {
    const previous = await ref(subscriptionId);
    const eventCreated = Math.max(previous?.eventCreated ?? 0, at ?? 0) || undefined;
    await opts.storage.put(`stripe-subscriptions/${subscriptionId}`, { accountId, ...(eventCreated ? { eventCreated } : {}) });
  }

  /** M3: `checkout.session.completed` / `async_payment_succeeded` grant the plan only when everything checks out. */
  async function checkoutPaid(session: Record<string, unknown>, at: number | undefined): Promise<boolean> {
    const accountId = identifier(session.client_reference_id) ?? identifier(object(session.metadata)?.accountId);
    const customerId = identifier(session.customer); const subscriptionId = identifier(session.subscription);
    if (session.mode !== 'subscription' || (session.status !== undefined && session.status !== 'complete')
      || (session.payment_status !== 'paid' && session.payment_status !== 'no_payment_required')
      || !accountId || !customerId || !subscriptionId) return false;
    if (!await opts.accounts.get(accountId)) return false;
    const current = await subscription(subscriptionId);
    if (identifier(current.customer) !== customerId || !GRANTING.has(current.status as string) || !hasPrice(current, opts.priceId)) return false;
    await opts.accounts.setPlan(accountId, 'paid', { customerId, subscriptionId });
    await remember(subscriptionId, accountId, at);
    return true;
  }
  /** `async_payment_failed`: the delayed payment never arrived; the account loses a plan this checkout gave it. */
  async function checkoutFailed(session: Record<string, unknown>): Promise<boolean> {
    const accountId = identifier(session.client_reference_id) ?? identifier(object(session.metadata)?.accountId);
    const subscriptionId = identifier(session.subscription);
    if (!accountId || !subscriptionId) return false;
    const account = await opts.accounts.get(accountId);
    if (!account || account.subscriptionId !== subscriptionId || account.plan !== 'paid') return false;
    await opts.accounts.setPlan(account.id, 'free');
    return true;
  }
  /** `customer.subscription.updated` / `.deleted` for the account's current subscription, newest event wins. */
  async function subscriptionChanged(sub: Record<string, unknown>, deleted: boolean, at: number | undefined): Promise<boolean> {
    const subscriptionId = identifier(sub.id); const customerId = identifier(sub.customer);
    if (!subscriptionId) return false;
    const stored = await ref(subscriptionId);
    const account = stored ? await opts.accounts.get(stored.accountId) : null;
    if (!stored || !account || account.subscriptionId !== subscriptionId || (customerId && account.customerId && customerId !== account.customerId)) return false;
    // Stripe does not guarantee delivery order; an event older than one already applied is ignored.
    if (at !== undefined && stored.eventCreated !== undefined && at < stored.eventCreated) return false;
    const status = typeof sub.status === 'string' ? sub.status : '';
    let plan: 'free' | 'paid' | null = null;
    if (deleted || REVOKED.has(status)) plan = 'free';
    else if (ENTITLED.has(status)) plan = hasPrice(sub, opts.priceId) ? 'paid' : 'free';
    // A grant needs an orderable event; a revocation applies even without one.
    if (plan === 'paid' && at === undefined) plan = null;
    if (plan !== null && plan !== account.plan) await opts.accounts.setPlan(account.id, plan);
    await remember(subscriptionId, account.id, at);
    return plan !== null;
  }

  return {
    async handle(rawBody: Buffer, signatureHeader: string): Promise<{ received: true; applied: boolean; replayed: boolean }> {
      verifyStripeSignature(rawBody, signatureHeader, opts.endpointSecret, now());
      let event: Record<string, unknown> | null;
      try { event = object(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(rawBody))); } catch { return fail(); }
      const eventId = identifier(event?.id); const type = event?.type;
      if (!eventId || typeof type !== 'string' || type.length > 128) fail();
      const at = created(event?.created);
      const work = async () => {
        const replayKey = `stripe-events/${eventId}`;
        if (await opts.storage.get(replayKey)) return { received: true as const, applied: false, replayed: true };
        const payload = object(object(event?.data)?.object);
        let applied = false;
        if (payload && (type === 'checkout.session.completed' || type === 'checkout.session.async_payment_succeeded')) applied = await checkoutPaid(payload, at);
        else if (payload && type === 'checkout.session.async_payment_failed') applied = await checkoutFailed(payload);
        else if (payload && (type === 'customer.subscription.updated' || type === 'customer.subscription.deleted')) {
          applied = await subscriptionChanged(payload, type === 'customer.subscription.deleted', at);
        }
        // Written only after the event was handled: a 503 above leaves it unrecorded so Stripe's retry is processed.
        await opts.storage.put(replayKey, { receivedAt: new Date(now()).toISOString() });
        return { received: true as const, applied, replayed: false };
      };
      const result = tail.then(work); tail = result.then(() => undefined, () => undefined); return result;
    },
  };
}
export type Billing = ReturnType<typeof createBilling>;
