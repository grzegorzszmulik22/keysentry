import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { appSecretProvider } from '../../src/providers/app-secret.js';
import type { ProviderContext } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';

function context(): { ctx: ProviderContext; http: FakeHttp; logs: string[] } {
  const http = new FakeHttp();
  const logs: string[] = [];
  const log = {
    info: (message: string) => { logs.push(message); },
    warn: (message: string) => { logs.push(message); },
    error: (message: string) => { logs.push(message); },
    debug: (message: string) => { logs.push(message); },
  };
  return { ctx: { http, credentials: {}, log }, http, logs };
}

describe('app-secret provider', () => {
  it('generates a fresh 32-byte base64url secret by default with safe rotation metadata', async () => {
    const { ctx, http, logs } = context();
    const oldValue = `legacy.${randomBytes(20).toString('base64url')}`;
    const result = await appSecretProvider.rotate!(oldValue, ctx);
    const nextResult = await appSecretProvider.rotate!(oldValue, ctx);

    expect(appSecretProvider.id).toBe('app-secret');
    expect(appSecretProvider.method).toBe('generate');
    expect(/^[A-Za-z0-9_-]{43}$/.test(result.newValue)).toBe(true);
    expect(Buffer.from(result.newValue, 'base64url').length).toBe(32);
    expect(result.newValue === oldValue).toBe(false);
    expect(result.newValue === nextResult.newValue).toBe(false);
    expect(result.oldKeyRef).toBeNull();
    expect(result.newKeyRef).toBeNull();
    expect(result.oldRevoked).toBe(false);
    expect(result.companions).toBeUndefined();
    expect(result.notes?.includes(oldValue)).toBe(false);
    expect(result.notes?.includes(result.newValue)).toBe(false);
    expect(result.notes).toMatch(/sessions.*JWT|JWT.*sessions/i);
    expect(result.notes).toMatch(/invalid/i);
    expect(http.calls.length).toBe(0);
    expect(logs.length).toBe(0);
  });

  it('preserves a clear lowercase hex encoding', async () => {
    const { ctx } = context();
    const oldValue = randomBytes(32).toString('hex');
    const result = await appSecretProvider.rotate!(oldValue, ctx);

    expect(/^[0-9a-f]{64}$/.test(result.newValue)).toBe(true);
    expect(Buffer.from(result.newValue, 'hex').length).toBe(32);
    expect(result.newValue === oldValue).toBe(false);
  });

  it('preserves a clear uppercase hex encoding', async () => {
    const { ctx } = context();
    const oldValue = randomBytes(32).toString('hex').toUpperCase();
    const result = await appSecretProvider.rotate!(oldValue, ctx);

    expect(/^[0-9A-F]{64}$/.test(result.newValue)).toBe(true);
    expect(result.newValue === oldValue).toBe(false);
  });

  it('preserves standard base64 and its 32 bytes of entropy', async () => {
    const { ctx } = context();
    const oldValue = randomBytes(32).toString('base64');
    const result = await appSecretProvider.rotate!(oldValue, ctx);

    expect(/^[A-Za-z0-9+/]{43}=$/.test(result.newValue)).toBe(true);
    expect(Buffer.from(result.newValue, 'base64').length).toBe(32);
    expect(result.newValue === oldValue).toBe(false);
  });

  it('preserves base64url without introducing padding', async () => {
    const { ctx } = context();
    const oldValue = randomBytes(32).toString('base64url');
    const result = await appSecretProvider.rotate!(oldValue, ctx);

    expect(/^[A-Za-z0-9_-]{43}$/.test(result.newValue)).toBe(true);
    expect(Buffer.from(result.newValue, 'base64url').length).toBe(32);
    expect(result.newValue === oldValue).toBe(false);
  });

  it('verifies locally without echoing a secret or calling HTTP', async () => {
    const { ctx, http, logs } = context();
    const value = randomBytes(32).toString('base64url');
    const result = await appSecretProvider.verify(value, ctx);

    expect(result.ok).toBe(true);
    expect(JSON.stringify(result).includes(value)).toBe(false);
    expect(http.calls.length).toBe(0);
    expect(logs.length).toBe(0);
  });

  it('provides guidance about invalidated sessions and JWTs without sharing values', () => {
    const guidance = appSecretProvider.guidance();
    expect(guidance.steps.join(' ')).toMatch(/sessions/i);
    expect(guidance.steps.join(' ')).toMatch(/JWT/i);
    expect(guidance.steps.join(' ')).toMatch(/invalid/i);
  });
});
