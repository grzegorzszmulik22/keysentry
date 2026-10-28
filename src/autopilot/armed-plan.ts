import { createHash, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { z } from 'zod';
import type { ArmedCluster, ArmedPlan, AutopilotMethod, Cluster, HostId, Inventory, ProviderId } from '../types.js';
import { classify } from '../core/classify.js';
import { serviceKey } from '../core/service-key.js';
import { getProvider, PROVIDER_CREDENTIALS, rotationIdentifiesOldKey } from '../providers/index.js';
import { canonicalJson, signDetached, verifyDetached, type DeviceKey } from '../security/index.js';
import { HOST_IDS } from '../types.js';

export const ARMED_PLAN_PREFIX = 'keysentry-armed-plan:v1\n';
const DAY_MS = 86_400_000;
const FORMAT_REASON = 'Armed plan format is invalid.';

// Cluster has no adoption member in the shared contract yet. The local CLI may
// attach this metadata after a supervised rotation; signed plans carry it onward.
type AdoptableCluster = Cluster & { adopted?: ArmedCluster['adopted'] };
type PlanBody = Omit<ArmedPlan, 'signer' | 'sig'>;
type Eligibility = { eligible: true; method: AutopilotMethod } | { eligible: false; reason: string };

const hostSchema = z.enum(HOST_IDS);
const providerSchema = z.enum(Object.keys(PROVIDER_CREDENTIALS) as [ProviderId, ...ProviderId[]]);
const metadata = z.string().min(1).max(4096).refine(value => !/[\u0000-\u001f\u007f]/.test(value));
const fingerprintSchema = z.string().min(1).max(256);
const dateSchema = z.iso.datetime({ offset: true });
const base64Schema = z.string().min(4).max(4096)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/)
  .refine(value => Buffer.from(value, 'base64').toString('base64') === value);
const positiveInteger = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const adoptedSchema = z.object({ fingerprint: fingerprintSchema, keyRef: metadata.nullable(), at: dateSchema }).strict();
const consumerSchema = z.object({ serviceKey: metadata, varName: metadata, fingerprint: fingerprintSchema.nullable() }).strict();
const clusterSchema = z.object({
  clusterId: metadata, provider: providerSchema, method: z.enum(['auto', 'generate']),
  consumers: z.array(consumerSchema).min(1), adopted: adoptedSchema.optional(),
}).strict().refine(cluster => {
  const identities = cluster.consumers.map(consumer => JSON.stringify([consumer.serviceKey, consumer.varName]));
  return new Set(identities).size === identities.length;
});

function healthUrlAllowed(value: string): boolean {
  try {
    const url = new URL(value);
    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    // URL normalisation discards an empty user-info component ("@host").
    const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#\\]*)/i.exec(value)?.[1];
    return url.protocol === 'https:' && url.username === '' && url.password === ''
      && !!authority && !authority.includes('@') && url.port === ''
      && hostname.length > 0 && isIP(hostname) === 0;
  } catch { return false; }
}

function validTimeZone(value: string): boolean {
  try { new Intl.DateTimeFormat('en', { timeZone: value }); return true; }
  catch { return false; }
}

const planBodySchema = z.object({
  v: z.literal(1), id: z.string().regex(/^arm-\d{8}-[a-f0-9]{8}$/), projectId: metadata,
  createdAt: dateSchema, expiresAt: dateSchema,
  hosts: z.array(hostSchema).min(1).max(6).refine(hosts => new Set(hosts).size === hosts.length),
  clusters: z.array(clusterSchema).max(500).refine(clusters => new Set(clusters.map(c => c.clusterId)).size === clusters.length),
  maxServicesPerWave: positiveInteger,
  graceSeconds: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  healthChecks: z.array(z.object({
    serviceKey: metadata, url: z.string().max(8192).refine(healthUrlAllowed),
    expectStatus: z.number().int().min(100).max(599).optional(),
  }).strict()).max(50),
  nextDeployAcceptance: z.array(z.object({
    host: hostSchema, maxHours: z.number().finite().positive(), revokeAfterMax: z.boolean(),
  }).strict()).max(6).refine(acceptances => new Set(acceptances.map(a => a.host)).size === acceptances.length),
  quiet: z.object({
    lowPriorityHours: z.object({
      start: z.string().regex(/^(?:[01]\d|2[0-3]):[0-5]\d$/),
      end: z.string().regex(/^(?:[01]\d|2[0-3]):[0-5]\d$/),
      timeZone: z.string().min(1).max(256).refine(validTimeZone),
    }).strict().optional(),
  }).strict(),
}).strict();

function validLifetime(plan: { createdAt: string; expiresAt: string }): boolean {
  const duration = Date.parse(plan.expiresAt) - Date.parse(plan.createdAt);
  return duration > 0 && duration <= 365 * DAY_MS;
}

const signedPlanSchema = planBodySchema.extend({
  signer: z.object({ keyId: z.string().regex(/^[a-f0-9]{16}$/), publicKeyDer: base64Schema }).strict(),
  sig: base64Schema,
}).strict().refine(validLifetime);

/** Write-only adoption needs a usable provider reference, never a retained plaintext value. */
export function adoptionNeeded(cluster: Cluster): boolean {
  const writeOnly = cluster.consumers.some(consumer => consumer.sealed || consumer.service.host === 'fly' || consumer.service.host === 'github-actions');
  if (!writeOnly) return false;
  if ((cluster as AdoptableCluster).adopted?.keyRef == null) return true;
  try { return typeof getProvider(cluster.provider).rotateByRef !== 'function'; }
  catch { return true; }
}

/** Eligibility is a capability check, never evidence that credentials are usable. */
export function autopilotEligibility(cluster: Cluster): Eligibility {
  const refuse = (reason: string): Eligibility => ({ eligible: false, reason });
  if (cluster.provider === 'stripe') return refuse('Stripe keys are never rotated automatically.');
  if (cluster.tier === 'payments') return refuse('Payment keys are never rotated automatically.');
  if (cluster.tier === 'database' || cluster.provider === 'database' || cluster.provider === 'supabase') {
    return refuse('Database keys are never rotated automatically.');
  }
  if (cluster.provider === 'encryption-key') return refuse('Encryption keys are never rotated automatically.');
  if (cluster.tier === 'crypto' || cluster.provider === 'crypto-wallet') return refuse('Wallet keys are never rotated automatically.');
  if (cluster.provider === 'private-key') return refuse('Private keys are never rotated automatically.');
  if (cluster.consumers.length === 0) return refuse('The cluster has no consumers.');
  // Inventory plans Google service-account JSON keys and public (client-side) API keys as guided (methodForValue).
  if (cluster.provider === 'google' && cluster.method === 'guided') {
    return refuse('Google service-account keys and public (client-side) Google API keys are always rotated by a person, so they cannot be armed.');
  }

  let adapter;
  try { adapter = getProvider(cluster.provider); }
  catch { return refuse('This provider does not support automatic rotation.'); }
  if (cluster.method === 'atomic-roll' || adapter.method === 'atomic-roll') return refuse('Atomic key rolls need approval.');
  if (cluster.method !== adapter.method) return refuse('The inventory rotation method does not match the provider.');
  if (adapter.method === 'guided') return refuse('This provider needs a guided rotation.');

  if (adapter.method === 'generate') {
    // The provider does not export the allow-list named in the plan. Reuse the
    // classifier's exact-name decision rather than duplicating or broadening it.
    if (cluster.provider !== 'app-secret' || cluster.tier !== 'app'
      || cluster.consumers.some(consumer => classify(consumer.varName, undefined).provider !== 'app-secret')) {
      return refuse('Only allow-listed application secrets can be generated automatically.');
    }
    if (typeof adapter.rotate !== 'function' || typeof adapter.verify !== 'function') {
      return refuse('This provider cannot generate and verify an application secret.');
    }
  } else if (adapter.method !== 'auto' || typeof adapter.rotate !== 'function'
    || typeof adapter.revoke !== 'function' || typeof adapter.verify !== 'function') {
    return refuse('This provider cannot create, verify and revoke keys automatically.');
  } else if (!rotationIdentifiesOldKey(cluster.provider)) {
    // An armed wave would leave the possibly compromised old key valid (rotate returns no old key reference).
    return refuse('This provider cannot identify the old key, so an unattended rotation would leave it valid. Rotate it with supervision and delete the old key yourself.');
  }
  if (adoptionNeeded(cluster)) return refuse('Write-only consumers need adoption before automatic rotation.');
  if ((cluster as AdoptableCluster).adopted && !adoptedSchema.safeParse((cluster as AdoptableCluster).adopted).success) {
    return refuse('The adoption record is invalid.');
  }
  return { eligible: true, method: adapter.method };
}

export function buildArmedPlan(input: {
  projectId: string; inventory: Inventory; clusterIds: string[]; hosts: HostId[];
  options: Partial<Pick<ArmedPlan, 'maxServicesPerWave' | 'graceSeconds' | 'healthChecks' | 'nextDeployAcceptance' | 'quiet'>> & { validDays?: number };
  now: Date;
}): { plan: PlanBody; refused: { clusterId: string; reason: string }[] } {
  const { options, now } = input;
  const validDays = options.validDays ?? 90;
  if (!Number.isFinite(now.getTime()) || !Number.isInteger(validDays) || validDays < 1 || validDays > 365) {
    throw new TypeError('Armed plan validity must be between 1 and 365 whole days, with a valid current date.');
  }
  const clusters: ArmedCluster[] = [];
  const refused: { clusterId: string; reason: string }[] = [];
  for (const clusterId of new Set(input.clusterIds)) {
    const cluster = input.inventory.clusters.find(cluster => cluster.id === clusterId);
    if (!cluster) { refused.push({ clusterId, reason: 'Cluster was not found in the inventory.' }); continue; }
    const eligibility = autopilotEligibility(cluster);
    if (!eligibility.eligible) { refused.push({ clusterId, reason: eligibility.reason }); continue; }
    const armed: ArmedCluster = {
      clusterId, provider: cluster.provider, method: eligibility.method,
      consumers: cluster.consumers.map(consumer => ({
        serviceKey: serviceKey(consumer.service), varName: consumer.varName, fingerprint: consumer.fingerprint,
      })),
    };
    const adopted = (cluster as AdoptableCluster).adopted;
    if (adopted) armed.adopted = { ...adopted };
    clusters.push(armed);
  }
  const plan = planBodySchema.safeParse({
    v: 1, id: `arm-${now.toISOString().slice(0, 10).replaceAll('-', '')}-${randomBytes(4).toString('hex')}`,
    projectId: input.projectId, createdAt: now.toISOString(), expiresAt: new Date(now.getTime() + validDays * DAY_MS).toISOString(),
    hosts: input.hosts, clusters, maxServicesPerWave: options.maxServicesPerWave ?? 10, graceSeconds: options.graceSeconds ?? 900,
    healthChecks: options.healthChecks ?? [], nextDeployAcceptance: options.nextDeployAcceptance ?? [], quiet: options.quiet ?? {},
  });
  if (!plan.success) throw new TypeError(FORMAT_REASON);
  return { plan: plan.data, refused };
}

export function signArmedPlan(plan: PlanBody, key: DeviceKey): ArmedPlan {
  const parsed = planBodySchema.safeParse(plan);
  if (!parsed.success || !validLifetime(parsed.data)) throw new TypeError(FORMAT_REASON);
  const keyId = createHash('sha256').update(key.publicKeyDer).digest('hex').slice(0, 16);
  if (keyId !== key.keyId) throw new TypeError('Device key ID does not match its public key.');
  const unsigned = { ...parsed.data, signer: { keyId, publicKeyDer: key.publicKeyDer.toString('base64') } };
  return { ...unsigned, sig: signDetached(key.privateKeyDer, Buffer.from(ARMED_PLAN_PREFIX + canonicalJson(unsigned), 'utf8')).toString('base64') };
}

/** Verify before checkScope and reverify before every unattended execution. */
export function verifyArmedPlan(plan: unknown, opts: { now: Date; trustedKeyIds: string[] }):
  { ok: true; plan: ArmedPlan } | { ok: false; reason: string } {
  try {
    const parsed = signedPlanSchema.safeParse(plan);
    if (!parsed.success) return { ok: false, reason: FORMAT_REASON };
    const { sig, ...unsigned } = parsed.data;
    const publicKey = Buffer.from(unsigned.signer.publicKeyDer, 'base64');
    const keyId = createHash('sha256').update(publicKey).digest('hex').slice(0, 16);
    if (keyId !== unsigned.signer.keyId) return { ok: false, reason: 'Armed plan signer key ID does not match its public key.' };
    if (!opts.trustedKeyIds.includes(keyId)) return { ok: false, reason: 'Armed plan signer is not trusted.' };
    if (!verifyDetached(publicKey, Buffer.from(ARMED_PLAN_PREFIX + canonicalJson(unsigned), 'utf8'), Buffer.from(sig, 'base64'))) {
      return { ok: false, reason: 'Armed plan signature is invalid.' };
    }
    const timestamp = opts.now.getTime();
    if (!Number.isFinite(timestamp)) return { ok: false, reason: 'The current date is invalid.' };
    if (Date.parse(unsigned.expiresAt) <= timestamp) return { ok: false, reason: 'Armed plan has expired.' };
    if (Date.parse(unsigned.createdAt) > timestamp + 300_000) return { ok: false, reason: 'Armed plan creation time is too far in the future.' };
    return { ok: true, plan: parsed.data };
  } catch { return { ok: false, reason: FORMAT_REASON }; }
}
