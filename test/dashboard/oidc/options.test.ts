import { describe, expect, it } from 'vitest';
import { parseListen, parseTeamUiOptions, teamAuditEvent } from '../../../src/dashboard/oidc/index.js';
import {
  createMemoryPasskeyCounters, createStatePasskeyCounters, TEAM_ROUTE_ROLES,
} from '../../../src/dashboard/server/index.js';
import { allows, createTeamSessions, readCookie, requiredRole } from '../../../src/dashboard/server/team.js';

const base = { publicOrigin: 'https://keysentry.example.test', oidcIssuer: 'https://idp.example.test', oidcClientId: 'keysentry' };

describe('ui --team options', () => {
  it('accepts a complete configuration with defaults', () => {
    expect(parseTeamUiOptions({ ...base, publicOrigin: 'https://keysentry.example.test/' })).toEqual({
      publicOrigin: 'https://keysentry.example.test', issuer: 'https://idp.example.test', clientId: 'keysentry', publicClient: false, hosts: [],
      listen: { host: '127.0.0.1', port: 8484 },
    });
    expect(parseTeamUiOptions({ ...base, oidcPublicClient: true, oidcHost: ['OAuth2.Example.test', 'oauth2.example.test.'], listen: '[::1]:9000' }))
      .toMatchObject({ publicClient: true, hosts: ['oauth2.example.test'], listen: { host: '::1', port: 9000 } });
    expect(parseListen('0.0.0.0:8484')).toEqual({ host: '0.0.0.0', port: 8484 });
  });

  it.each([
    [{ publicOrigin: undefined }, '--public-origin'],
    [{ publicOrigin: 'http://keysentry.example.test' }, '--public-origin'],
    [{ publicOrigin: 'https://keysentry.example.test/app' }, '--public-origin'],
    [{ publicOrigin: 'https://10.0.0.5' }, '--public-origin'],
    [{ publicOrigin: 'https://user:pw@keysentry.example.test' }, '--public-origin'],
    [{ publicOrigin: 'https://keysentry.example.test/?x=1' }, '--public-origin'],
    [{ oidcIssuer: 'http://idp.example.test' }, '--oidc-issuer'],
    [{ oidcIssuer: undefined }, '--oidc-issuer'],
    [{ oidcClientId: '' }, '--oidc-client-id'],
    [{ oidcClientId: 'has space' }, '--oidc-client-id'],
    [{ oidcHost: ['10.0.0.1'] }, '--oidc-host'],
    [{ oidcHost: ['https://oauth2.example.test'] }, '--oidc-host'],
    [{ listen: '8484' }, '--listen'],
    [{ listen: '127.0.0.1:0' }, '--listen'],
    [{ listen: '[localhost]:8484' }, '--listen'],
  ])('refuses %j', (change, flag) => {
    expect(() => parseTeamUiOptions({ ...base, ...change })).toThrow(flag);
  });

  it('writes value-free audit events', () => {
    const events = [
      teamAuditEvent({ kind: 'sign-in', memberId: 'ana', role: 'operator' }),
      teamAuditEvent({ kind: 'sign-in-refused', reason: 'not-member' }),
      teamAuditEvent({ kind: 'sign-out', memberId: 'ana' }),
      teamAuditEvent({ kind: 'session-ended', memberId: 'ana', reason: 'roster' }),
    ];
    expect(events.map(event => event.kind)).toEqual(['team-sign-in', 'team-sign-in-refused', 'team-sign-out', 'team-session-ended']);
    expect(events[1]).toEqual({ kind: 'team-sign-in-refused', summary: 'A dashboard sign-in was refused.', data: { reason: 'not-member' } });
  });
});

describe('team access helpers', () => {
  it('never lets a mutating route drop below operator, and keeps widening routes for admins', () => {
    expect(requiredRole('keys', { method: 'GET', mutating: false })).toBe('viewer');
    expect(requiredRole('autopilot/disarm', { method: 'POST', mutating: false })).toBe('operator');
    expect(requiredRole('rotate/preview', { method: 'POST', mutating: false })).toBe('viewer');
    expect(requiredRole('rotate/execute', { method: 'POST', mutating: true })).toBe('operator');
    expect(requiredRole('rotate/execute', { method: 'POST', mutating: true }, { 'rotate/execute': 'viewer' })).toBe('operator');
    expect(requiredRole('settings', { method: 'GET', mutating: false }, { settings: 'admin' })).toBe('admin');
    expect(requiredRole('x', { method: 'POST', mutating: true }, { x: 'owner' as never })).toBe('operator');
    for (const route of ['autopilot/arm', 'settings/update', 'notifications/add', 'notifications/remove', 'vault/store', 'vault/remove', 'reveal']) {
      expect(TEAM_ROUTE_ROLES[route]).toBe('admin');
    }
    expect(allows('admin', 'operator')).toBe(true);
    expect(allows('viewer', 'operator')).toBe(false);
    expect(allows('root' as never, 'viewer')).toBe(false);
  });

  it('reads exactly one well-formed cookie', () => {
    const id = 'a'.repeat(43);
    expect(readCookie(`x=1; __Host-ks_session=${id}`, '__Host-ks_session')).toBe(id);
    expect(readCookie(`__Host-ks_session=${id}; __Host-ks_session=${id}`, '__Host-ks_session')).toBeUndefined();
    expect(readCookie('__Host-ks_session=short', '__Host-ks_session')).toBeUndefined();
    expect(readCookie(`ks_session=${id}`, '__Host-ks_session')).toBeUndefined();
  });

  it('bounds sessions and expires them by idle and absolute time', () => {
    let now = 0;
    const sessions = createTeamSessions({ idleMs: 100, absoluteMs: 250, max: 2, now: () => now });
    const a = sessions.create({ memberId: 'a', email: 'a@x.test' });
    const b = sessions.create({ memberId: 'b', email: 'b@x.test' });
    const c = sessions.create({ memberId: 'c', email: 'c@x.test' });
    const cookie = (id: string) => `__Host-ks_session=${id}`;
    expect(sessions.authenticate(cookie(a.id))).toBeNull();
    expect(sessions.authenticate(cookie(b.id))?.memberId).toBe('b');
    now = 99; expect(sessions.authenticate(cookie(c.id))?.memberId).toBe('c');
    now = 198; expect(sessions.authenticate(cookie(c.id))?.memberId).toBe('c');
    now = 250; expect(sessions.authenticate(cookie(c.id))).toBeNull();
  });

  it('keeps passkey counters in encrypted state, monotonic and validated', async () => {
    const files = new Map<string, unknown>();
    const store = {
      paths: { dir: '/state' } as never,
      readJson: async (kind: string, path: string) => { expect(kind).toBe('passkeys'); return structuredClone(files.get(path) ?? null) as never; },
      writeJson: async (kind: string, path: string, data: unknown) => { expect(kind).toBe('passkeys'); files.set(path, structuredClone(data)); },
    };
    const counters = createStatePasskeyCounters(store);
    expect(await counters.read('cred1')).toBeNull();
    await counters.write('cred1', 5);
    await counters.write('cred1', 3);
    expect(await counters.read('cred1')).toBe(5);
    expect([...files.values()][0]).toEqual({ v: 1, counters: { cred1: 5 } });
    await expect(counters.write('bad id', 1)).rejects.toThrow();
    await expect(counters.write('cred2', -1)).rejects.toThrow();
    files.set([...files.keys()][0]!, { v: 1, counters: { cred1: 'five' } });
    await expect(counters.read('cred1')).rejects.toThrow('could not be read');
    const memory = createMemoryPasskeyCounters();
    await memory.write('x', 2); expect(await memory.read('x')).toBe(2);
  });
});
