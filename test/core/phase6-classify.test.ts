import { describe, expect, it } from 'vitest';
import { buildInventory, classify, methodFor, methodForValue } from '../../src/core/index.js';
import { autopilotEligibility } from '../../src/autopilot/armed-plan.js';
import { createRedactor } from '../../src/core/redact.js';
import { svc } from '../helpers/fakes.js';

const random = 'aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW1xY';
const hex = '0123456789abcdef'.repeat(2);
const serviceAccount = JSON.stringify({ type: 'service_account', project_id: 'demo', private_key_id: 'abc',
  private_key: '-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n', client_email: 'svc@demo.iam.gserviceaccount.com' });

describe('phase 6 classifier rules (notes/providers-a.md, notes/providers-b.md)', () => {
  it.each([
    ['GROQ_API_KEY', `gsk_${random}`, 'groq', true],
    ['ANY_NAME', `r8_${random}`, 'replicate', true],
    ['NEON_API_KEY', `napi_${random}${random}`, 'neon', true],
    ['MISTRAL_API_KEY', random, 'mistral', true],
    ['CLERK_SECRET_KEY', `sk_live_${random}`, 'clerk', true],
    ['CLERK_WEBHOOK_SECRET', `whsec_${random}`, 'clerk', true],
    ['NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY', `pk_live_${random}`, 'clerk', false],
    ['STRIPE_SECRET_KEY', `sk_live_${random}`, 'stripe', true],
    ['STRIPE_PUBLISHABLE_KEY', `pk_live_${random}`, 'stripe', false],
    ['TWILIO_API_KEY', `SK${hex}`, 'twilio', false],
    ['TWILIO_ACCOUNT_SID', `AC${hex}`, 'twilio', false],
    ['TWILIO_API_SECRET', random, 'twilio', true],
    ['TWILIO_AUTH_TOKEN', hex, 'twilio', true],
    ['POSTMARK_SERVER_TOKEN', '7c1f8a2e-6b3d-4f9a-8e2c-5d4b3a2f1e0c', 'postmark', true],
    ['POSTMARK_SERVER_TOKEN', 'POSTMARK_API_TEST', 'postmark', false],
    ['SOME_UUID', '7c1f8a2e-6b3d-4f9a-8e2c-5d4b3a2f1e0c', 'unknown', false],
    ['REDIS_URL', `rediss://default:${random}@eu1-fine-cat-12345.upstash.io:6379`, 'upstash', true],
    ['DATABASE_URL', `postgres://user:${random}@ep-cool-1.eu-central-1.aws.neon.tech/db`, 'database', true],
    ['UPSTASH_REDIS_REST_TOKEN', random, 'upstash', true],
    ['KV_REST_API_TOKEN', random, 'upstash', true],
    ['QSTASH_TOKEN', random, 'upstash', true],
    ['GEMINI_API_KEY', random, 'google', true],
    ['DATABASE_URL', '${db.DATABASE_URL}', 'unknown', false],
  ])('%s=%s is %s (secret: %s)', (name, value, provider, isSecret) => {
    expect(classify(name, value)).toMatchObject({ provider, isSecret });
  });

  it('rotation methods follow the adapters', () => {
    expect(methodFor('google')).toBe('auto');
    expect(methodFor('sendgrid')).toBe('auto');
    expect(methodFor('twilio')).toBe('auto');
    expect(methodFor('neon')).toBe('auto');
    expect(methodFor('upstash')).toBe('atomic-roll');
    for (const provider of ['groq', 'mistral', 'replicate', 'postmark', 'clerk'] as const) expect(methodFor(provider)).toBe('guided');
  });

  it('pattern redaction masks the new value shapes but leaves Twilio SIDs readable', () => {
    const redactor = createRedactor();
    for (const value of [`gsk_${random}`, `r8_${random}`, `napi_${random}${random}`]) expect(redactor.redact(`x ${value} y`)).not.toContain(value);
    expect(redactor.redact(`SK${hex}`)).toBe(`SK${hex}`);
  });
});

describe('Google service-account JSON keys (decision 4)', () => {
  it('are classified as Google secrets but always planned as guided', () => {
    expect(classify('GOOGLE_APPLICATION_CREDENTIALS_JSON', serviceAccount)).toMatchObject({ provider: 'google', isSecret: true });
    expect(methodForValue('google', serviceAccount)).toBe('guided');
    expect(methodForValue('google', `AIza${random}abc`)).toBe('auto');
  });

  it('inventory marks a service-account cluster guided, and arming refuses it with a clear message', () => {
    const service = svc('railway', 'api');
    const inventory = buildInventory([{ host: 'railway', services: [{ service, vars: [
      { name: 'GOOGLE_SERVICE_ACCOUNT', value: serviceAccount, sealed: false },
      { name: 'GOOGLE_API_KEY', value: `AIza${random}abc`, sealed: false },
    ] }] }], Buffer.alloc(32, 7));
    const json = inventory.clusters.find(cluster => cluster.consumers[0]!.varName === 'GOOGLE_SERVICE_ACCOUNT')!;
    const apiKey = inventory.clusters.find(cluster => cluster.consumers[0]!.varName === 'GOOGLE_API_KEY')!;
    expect(json).toMatchObject({ provider: 'google', method: 'guided' });
    expect(apiKey).toMatchObject({ provider: 'google', method: 'auto' });
    expect(autopilotEligibility(json)).toEqual({ eligible: false, reason: 'Google service-account keys are always rotated by a person, so they cannot be armed.' });
    expect(autopilotEligibility(apiKey)).toMatchObject({ eligible: true, method: 'auto' });
  });
});
