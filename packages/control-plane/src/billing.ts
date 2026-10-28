import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Storage } from './storage.js';

interface BillingAccount { id: string; plan: 'free' | 'paid'; customerId?: string; subscriptionId?: string }
export interface BillingOptions {
  storage: Storage;
  accounts: {
    get(accountId: string): Promise<BillingAccount | null>;
    setPlan(accountId: string, plan: 'free' | 'paid', billing?: { customerId?: string; subscriptionId?: string }): Promise<void>;
  };
  endpointSecret: string;
  now?: () => number;
}
function fail(): never { throw new Error('Billing webhook could not be verified.'); }
function identifier(value: unknown): string | undefined { return typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value) ? value : undefined; }
function object(value: unknown): Record<string, unknown> | null { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null; }

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

/** Billing sees account references and plan identifiers, never provider credentials. */
export function createBilling(opts: BillingOptions) {
  if (!opts.endpointSecret) throw new Error('Billing endpoint secret is required.');
  let tail: Promise<unknown> = Promise.resolve();
  return {
    async handle(rawBody: Buffer, signatureHeader: string): Promise<{ received: true; applied: boolean; replayed: boolean }> {
      verifyStripeSignature(rawBody, signatureHeader, opts.endpointSecret, (opts.now ?? Date.now)());
      let event: Record<string, unknown> | null;
      try { event = object(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(rawBody))); } catch { return fail(); }
      const eventId = identifier(event?.id); const type = event?.type;
      if (!eventId || typeof type !== 'string' || type.length > 128) fail();
      const work = async () => {
        const replayKey = `stripe-events/${eventId}`;
        if (await opts.storage.get(replayKey)) return { received: true as const, applied: false, replayed: true };
        const payload = object(object(event?.data)?.object);
        let applied = false;
        if (type === 'checkout.session.completed' && payload) {
          const accountId = identifier(payload.client_reference_id) ?? identifier(object(payload.metadata)?.accountId);
          const customerId = identifier(payload.customer); const subscriptionId = identifier(payload.subscription);
          if (accountId && await opts.accounts.get(accountId)) {
            await opts.accounts.setPlan(accountId, 'paid', { customerId, subscriptionId });
            if (customerId) await opts.storage.put(`stripe-customers/${customerId}`, { accountId });
            if (subscriptionId) await opts.storage.put(`stripe-subscriptions/${subscriptionId}`, { accountId });
            applied = true;
          }
        } else if (type === 'customer.subscription.deleted' && payload) {
          const subscriptionId = identifier(payload.id); const customerId = identifier(payload.customer);
          const ref = subscriptionId ? await opts.storage.get<{ accountId: string }>(`stripe-subscriptions/${subscriptionId}`) : null;
          const fallback = !ref && customerId ? await opts.storage.get<{ accountId: string }>(`stripe-customers/${customerId}`) : null;
          const accountId = ref?.accountId ?? fallback?.accountId;
          const account = accountId ? await opts.accounts.get(accountId) : null;
          if (account && subscriptionId && account.subscriptionId === subscriptionId && (!customerId || !account.customerId || customerId === account.customerId)) {
            await opts.accounts.setPlan(account.id, 'free'); applied = true;
          }
        }
        await opts.storage.put(replayKey, { receivedAt: new Date((opts.now ?? Date.now)()).toISOString() });
        return { received: true as const, applied, replayed: false };
      };
      const result = tail.then(work); tail = result.then(() => undefined, () => undefined); return result;
    },
  };
}
export type Billing = ReturnType<typeof createBilling>;
