// fix-phase6: classification and redaction decisions (notes/fix-phase6.md H1, M1, L2).
import { describe, expect, it } from 'vitest';
import {
  buildInventory, buildPlan, classify, createRedactor, isPublicGoogleKeyName, isPublicKeyIdentifier, methodForValue,
  PUBLIC_GOOGLE_KEY_EXPLANATION, renderBlastRadius, renderRunbook,
} from '../../src/core/index.js';
import type { RawVariable, ServiceRef } from '../../src/types.js';

const key = Buffer.alloc(32, 0x61);
const googleKey = `AIzaSy${'C'.repeat(12)}x${'y'.repeat(12)}Q-z_${'w'.repeat(4)}`; // AIza + 35 characters
const service = (id: string): ServiceRef => ({
  host: 'vercel', projectId: 'web', projectName: 'web', serviceId: id, serviceName: id, environmentId: 'production', environmentName: 'production',
});
const inventory = (vars: Record<string, Record<string, string>>) => buildInventory([{ host: 'vercel', services: Object.entries(vars)
  .map(([id, values]) => ({ service: service(id), vars: Object.entries(values).map(([name, value]): RawVariable => ({ name, value, sealed: false })) })) }], key);

describe('public Google API keys (H1)', () => {
  it.each([
    'NEXT_PUBLIC_FIREBASE_API_KEY', 'VITE_GOOGLE_MAPS_API_KEY', 'EXPO_PUBLIC_FIREBASE_API_KEY', 'REACT_APP_GOOGLE_API_KEY',
    'PUBLIC_MAPS_KEY', 'NUXT_PUBLIC_GOOGLE_KEY', 'GATSBY_GOOGLE_KEY', 'VUE_APP_MAPS_KEY', 'FIREBASE_API_KEY', 'FIREBASE_WEB_API_KEY',
    'GOOGLE_MAPS_BROWSER_KEY', 'MAPS_JS_API_KEY', 'GOOGLE_MAPS_JAVASCRIPT_KEY', 'GOOGLE_ANDROID_API_KEY', 'GOOGLE_IOS_API_KEY',
  ])('%s is a public key: inventoried as a Google secret but always guided', (name) => {
    expect(isPublicGoogleKeyName(name)).toBe(true);
    const c = classify(name, googleKey);
    expect(c).toMatchObject({ provider: 'google', isSecret: true });
    expect(methodForValue(c.provider, googleKey, name)).toBe('guided');
  });

  it.each(['FIREBASE_SERVICE_ACCOUNT', 'FIREBASE_ADMIN_KEY', 'FIREBASE_TOKEN', 'FIREBASE_PRIVATE_KEY', 'GOOGLE_CLIENT_CREDENTIALS'])(
    '%s is a real secret, never public config', (name) => {
      expect(isPublicGoogleKeyName(name)).toBe(false);
    });

  it.each(['GEMINI_API_KEY', 'GOOGLE_API_KEY', 'GOOGLE_GENERATIVE_AI_API_KEY', 'GOOGLE_MAPS_API_KEY', 'GOOGLE_MAPS_SERVER_KEY', 'SITEMAP_KEY'])(
    '%s stays automatic (a server-side key)', (name) => {
      expect(isPublicGoogleKeyName(name)).toBe(false);
      expect(methodForValue(classify(name, googleKey).provider, googleKey, name)).toBe('auto');
    });

  it('makes the whole cluster guided when one consumer ships the key to clients', () => {
    const inv = inventory({ api: { GEMINI_API_KEY: googleKey }, web: { NEXT_PUBLIC_GEMINI_KEY: googleKey } });
    expect(inv.clusters).toHaveLength(1);
    expect(inv.clusters[0]).toMatchObject({ provider: 'google', method: 'guided' });
    expect(inventory({ api: { GEMINI_API_KEY: googleKey } }).clusters[0]!.method).toBe('auto');
  });

  it('explains the public key in the runbook and blast radius, with guided steps and no automatic deletion', () => {
    const inv = inventory({ web: { NEXT_PUBLIC_FIREBASE_API_KEY: googleKey } });
    const runbook = renderRunbook(buildPlan(inv), inv);
    expect(runbook).toContain(PUBLIC_GOOGLE_KEY_EXPLANATION);
    expect(runbook).toMatch(/Delete the old key yourself, only after the shipped apps/);
    expect(runbook).not.toContain('Create a replacement with the provider API');
    expect(renderBlastRadius(inv)).toContain(PUBLIC_GOOGLE_KEY_EXPLANATION);
    expect(runbook).not.toContain(googleKey);
  });
});

describe('guided-only credentials planned up front (L2)', () => {
  it('plans Twilio Auth Tokens as guided and keeps API key secrets automatic', () => {
    const authToken = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
    expect(methodForValue('twilio', authToken, 'TWILIO_AUTH_TOKEN')).toBe('guided');
    expect(methodForValue('twilio', authToken, 'TWILIO_TOKEN')).toBe('guided');
    expect(methodForValue('twilio', 'Zq3Lp9Xv2Kd8Nw4Rt6Ym1Hs5Bc7Fg0Ja', 'TWILIO_API_SECRET')).toBe('auto');
  });

  it('plans Neon keys named for an organization or project as guided', () => {
    const value = `napi_${'k'.repeat(40)}`;
    expect(methodForValue('neon', value, 'NEON_ORG_API_KEY')).toBe('guided');
    expect(methodForValue('neon', value, 'NEON_PROJECT_API_KEY')).toBe('guided');
    expect(methodForValue('neon', value, 'NEON_API_KEY')).toBe('auto');
  });
});

describe('public key identifiers are never registered as secrets (M1)', () => {
  it('keeps AWS access key ids and Twilio key SIDs readable while masking every secret', () => {
    const redactor = createRedactor();
    const awsId = 'AKIAABCDEFGHIJKLMNOP';
    const sid = `SK${'0123456789abcdef'.repeat(2)}`;
    const secret = 'opaque-registered-secret-value';
    for (const value of [awsId, sid, secret]) redactor.register(value);
    expect(isPublicKeyIdentifier(awsId)).toBe(true);
    expect(isPublicKeyIdentifier(sid)).toBe(true);
    expect(isPublicKeyIdentifier(`AC${'0'.repeat(32)}`)).toBe(false);
    expect(redactor.redact(`${awsId} ${sid} ${secret}`)).toBe(`${awsId} ${sid} «redacted»`);
  });
});
