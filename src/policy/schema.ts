// Strict shape of the signed team policy (policy-as-code). Rules can only narrow local configuration.
import { isIP } from 'node:net';
import { z } from 'zod';
import { HOST_IDS, TIER_ORDER } from '../types.js';
import type { NotifyChannelKind, ProviderId, RiskTier, SignedTeamPolicy, TeamPolicy } from '../types.js';
import { isoDate, sha256Hex, signatureSchema, teamIdPattern, MAX_SIGNATURES } from '../team/schema.js';

export const PROVIDER_IDS = ['openai', 'anthropic', 'openrouter', 'stripe', 'resend', 'cloudflare', 'github', 'aws', 'supabase', 'database',
  'slack', 'sendgrid', 'twilio', 'google', 'groq', 'mistral', 'replicate', 'postmark', 'clerk', 'upstash', 'neon', 'private-key',
  'crypto-wallet', 'app-secret', 'encryption-key', 'unknown'] as const satisfies readonly ProviderId[];
// Compile-time check that every ProviderId is listed.
const everyProvider: [Exclude<ProviderId, typeof PROVIDER_IDS[number]>] extends [never] ? true : never = true;
void everyProvider;

export const NOTIFY_KINDS = ['telegram', 'discord', 'slack', 'ntfy', 'webhook', 'resend', 'smtp', 'console'] as const satisfies readonly NotifyChannelKind[];
const everyKind: [Exclude<NotifyChannelKind, typeof NOTIFY_KINDS[number]>] extends [never] ? true : never = true;
void everyKind;

const unique = <T>(values: T[]) => new Set(values).size === values.length;
const count = z.number().int().min(1).max(50);
export const MAX_GRACE_SECONDS = 7 * 24 * 60 * 60;

/** Exact lowercase DNS names, no IP literals and no wildcards: the same rule as network.allowHosts in keysentry.yaml. */
export const policyHostname = z.string().max(253).refine(value => {
  if (value !== value.toLowerCase() || !value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return false;
  try { return new URL(`https://${value}`).hostname === value && isIP(value) === 0; } catch { return false; }
});

const tierCounts = z.object(Object.fromEntries(TIER_ORDER.map(tier => [tier, count.optional()])) as Record<RiskTier, z.ZodOptional<typeof count>>).strict();

const sections = {
  autopilot: z.object({
    allowedHosts: z.array(z.enum(HOST_IDS)).max(HOST_IDS.length).refine(unique).optional(),
    allowedProviders: z.array(z.enum(PROVIDER_IDS)).max(PROVIDER_IDS.length).refine(unique).optional(),
    maxServicesPerWave: z.number().int().min(1).max(1000).optional(),
    approvalTiers: z.array(z.enum(TIER_ORDER as unknown as [RiskTier, ...RiskTier[]])).max(TIER_ORDER.length).refine(unique).optional(),
  }).strict(),
  approvals: z.object({ required: count, requiredByTier: tierCounts.optional(), wideningAdmins: count }).strict(),
  network: z.object({
    offline: z.boolean().optional(),
    allowHosts: z.array(policyHostname).max(500).refine(unique).optional(),
    requireProxy: z.boolean().optional(),
  }).strict(),
  notify: z.object({ allowedKinds: z.array(z.enum(NOTIFY_KINDS)).max(NOTIFY_KINDS.length).refine(unique).optional() }).strict(),
  rotation: z.object({
    revoke: z.enum(['after-deploy', 'never']).optional(),
    minGraceSeconds: z.number().int().min(0).max(MAX_GRACE_SECONDS).optional(),
  }).strict(),
  audit: z.object({ exportRequired: z.boolean().optional() }).strict(),
};

export const policySchema = z.object({
  v: z.literal(1),
  teamId: z.string().regex(teamIdPattern),
  version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  prev: sha256Hex.nullable(),
  updatedAt: isoDate,
  ...sections,
}).strict();

export const signedPolicySchema = z.object({ policy: policySchema, signatures: z.array(signatureSchema).max(MAX_SIGNATURES) }).strict();

/**
 * An unsigned draft an admin writes by hand: the chain fields may be left out (`policy sign` fills them in), and
 * sections may be omitted. Approvals default to one approver and one admin for policy-widening actions.
 */
export const draftSchema = z.object({
  v: z.literal(1).optional(),
  teamId: z.string().regex(teamIdPattern).optional(),
  version: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).optional(),
  prev: sha256Hex.nullable().optional(),
  updatedAt: isoDate.optional(),
  autopilot: sections.autopilot.optional(),
  approvals: z.object({ required: count.optional(), requiredByTier: tierCounts.optional(), wideningAdmins: count.optional() }).strict().optional(),
  network: sections.network.optional(),
  notify: sections.notify.optional(),
  rotation: sections.rotation.optional(),
  audit: sections.audit.optional(),
}).strict();

export type PolicyDraft = z.infer<typeof draftSchema>;

export function parseSignedPolicy(input: unknown): { ok: true; value: SignedTeamPolicy } | { ok: false; reason: string } {
  const parsed = signedPolicySchema.safeParse(input);
  if (!parsed.success) {
    const fields = [...new Set(parsed.error.issues.map(issue => issue.path.filter(part => typeof part === 'string').slice(0, 3).join('.') || 'policy'))].slice(0, 5);
    return { ok: false, reason: `The policy is not a valid signed team policy: check ${fields.join(', ')} (wrong type, unknown field, or invalid value).` };
  }
  const policy = parsed.data.policy;
  if ((policy.version === 1) !== (policy.prev === null)) return { ok: false, reason: 'Version 1 of a policy has no previous hash, and every later version has one.' };
  const seen = new Set<string>();
  for (const signature of parsed.data.signatures) {
    const key = `${signature.memberId}:${signature.keyId}`;
    if (seen.has(key)) return { ok: false, reason: 'The policy carries the same signature twice.' };
    seen.add(key);
  }
  return { ok: true, value: parsed.data as SignedTeamPolicy };
}

export type { TeamPolicy };
