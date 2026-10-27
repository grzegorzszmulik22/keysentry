import { expect, test } from 'vitest';
import { makeResponse } from '../../src/http.js';
import { createGuardedHttp, EGRESS_RULES, EgressBlockedError } from '../../src/net/index.js';
import type { NetworkReceipt, NetworkReceiptEntry } from '../../src/types.js';
import { FakeHttp } from '../helpers/fake-http.js';

const credentialHeaders = {
  aUtHoRiZaTiOn: 'bearer-value',
  authorization: 'other-bearer-value',
  'PrOxY-AuThOrIzAtIoN': 'proxy-value',
  CoOkIe: 'session-value',
  apikey: 'service-role-jwt-value',
  'Api-Key': 'api-key-value',
  'x-api-key': 'another-credential',
  'X-AuTh-ToKeN': 'auth-token-value',
  'X-GoOg-ApI-KeY': 'google-key-value',
  'OpEnAi-OrGaNiZaTiOn': 'organization-value',
  'AnThRoPiC-ApI-KeY': 'anthropic-key-value',
  'X-Custom-ToKeN-Id': 'custom-token-value',
  'X-Custom-SeCrEt-Id': 'custom-secret-value',
  'X-Custom-KeY-Id': 'custom-key-value',
  'X-Custom-AuTh-Id': 'custom-auth-value',
};

// Regression from the independent L3 probe. The orchestrator requires rejection of this
// cross-project redirect, so no second request (even one with stripped headers) is allowed.
test.each([301, 302, 303, 307, 308])('Supabase redirect %i cannot send credentials to another project', async status => {
  const inner = new FakeHttp()
    .on('GET', /victimproject\.supabase\.co/, () => makeResponse(status, '', { location: 'https://attacker-project.supabase.co/collect' }))
    .on('GET', /attacker-project\.supabase\.co/, () => makeResponse(200, '{}'));
  const entries: NetworkReceiptEntry[] = [];
  const receipt: NetworkReceipt = { async record(entry) { entries.push(entry); }, async summarize() { return []; } };
  const request = {
    method: 'GET' as const, url: 'https://victimproject.supabase.co/rest/v1/',
    headers: { apikey: 'service-role-jwt-value', 'x-api-key': 'another-credential', Authorization: 'Bearer service-role-jwt-value' },
  };
  await expect(createGuardedHttp(inner, { rules: EGRESS_RULES, receipt }).request(request)).rejects.toMatchObject({
    name: 'EgressBlockedError', code: 'EGRESS_BLOCKED',
    message: 'Blocked a request to attacker-project.supabase.co: it is not on keysentry\'s list of allowed hosts. Run "keysentry network" to see the list.',
  });
  expect(inner.calls).toHaveLength(1);
  expect(inner.calls[0]!.headers).toEqual(request.headers);
  expect(entries.map(({ host, allowed, status }) => ({ host, allowed, status }))).toEqual([
    { host: 'victimproject.supabase.co', allowed: true, status },
    { host: 'attacker-project.supabase.co', allowed: false, status: undefined },
  ]);
  expect(JSON.stringify(entries)).not.toMatch(/service-role-jwt-value|another-credential|Bearer|rest\/v1|collect/);
});

test.each(['feed', 'release', 'notify', 'user'])('%s cross-host redirects remove all credential headers without changing the caller', async owner => {
  const rules = [
    { host: 'first.example.com', owner, purpose: 'configured request' },
    { host: 'second.example.com', owner, purpose: 'configured target' },
  ];
  const inner = new FakeHttp()
    .on('GET', /first\.example\.com/, () => makeResponse(302, '', { location: 'https://second.example.com/result' }))
    .on('GET', /second\.example\.com/, () => makeResponse(200, 'ok'));
  const headers = { ...credentialHeaders, Accept: 'application/json', 'X-Trace-Id': 'trace-id' };
  const http = createGuardedHttp(inner, { rules });
  expect((await http.request({ method: 'GET', url: 'https://first.example.com/start', headers })).text).toBe('ok');
  expect(inner.calls).toHaveLength(2);
  expect(inner.calls[1]!.headers).toEqual({ Accept: 'application/json', 'X-Trace-Id': 'trace-id' });
  expect(headers).toEqual({ ...credentialHeaders, Accept: 'application/json', 'X-Trace-Id': 'trace-id' });
});

test.each([0, 1])('a forbidden provider target is recorded even after the redirect limit %i', async maxRedirects => {
  const entries: NetworkReceiptEntry[] = [];
  const receipt: NetworkReceipt = { async record(entry) { entries.push(entry); }, async summarize() { return []; } };
  const inner = new FakeHttp().on('GET', /victimproject\.supabase\.co/, () => makeResponse(307, '', {
    location: inner.calls.length <= maxRedirects ? '/again' : 'https://attacker-project.supabase.co/collect',
  }));
  await expect(createGuardedHttp(inner, { rules: EGRESS_RULES, receipt, maxRedirects }).request({
    method: 'GET', url: 'https://victimproject.supabase.co/start', headers: credentialHeaders,
  })).rejects.toBeInstanceOf(EgressBlockedError);
  expect(inner.calls).toHaveLength(maxRedirects + 1);
  expect(entries).toHaveLength(maxRedirects + 2);
  expect(entries.at(-1)).toMatchObject({ host: 'attacker-project.supabase.co', allowed: false });
});

test('same-host redirects preserve credential headers after hostname normalization', async () => {
  const rules = [{ host: 'api.example.com', owner: 'provider', purpose: 'provider request' }];
  const inner = new FakeHttp()
    .on('GET', /\/start$/, () => makeResponse(307, '', { location: 'https://API.EXAMPLE.COM.:443/result' }))
    .on('GET', /\/result$/, () => makeResponse(200, 'ok'));
  expect((await createGuardedHttp(inner, { rules }).request({
    method: 'GET', url: 'https://api.example.com/start', headers: credentialHeaders,
  })).text).toBe('ok');
  expect(inner.calls).toHaveLength(2);
  expect(inner.calls[1]!.headers).toEqual(credentialHeaders);
});

test('credentials stay removed when redirects return to the original host', async () => {
  const rules = [
    { host: 'first.example.com', owner: 'feed', purpose: 'feed request' },
    { host: 'second.example.com', owner: 'feed', purpose: 'feed target' },
  ];
  const inner = new FakeHttp()
    .on('GET', /first\.example\.com\/start$/, () => makeResponse(307, '', { location: 'https://second.example.com/next' }))
    .on('GET', /second\.example\.com/, () => makeResponse(307, '', { location: 'https://first.example.com/result' }))
    .on('GET', /first\.example\.com\/result$/, () => makeResponse(200, 'ok'));
  await createGuardedHttp(inner, { rules }).request({ method: 'GET', url: 'https://first.example.com/start', headers: credentialHeaders });
  expect(inner.calls).toHaveLength(3);
  expect(inner.calls.slice(1).map(call => call.headers)).toEqual([{}, {}]);
});

test.each([
  ['https://www.theregister.com/headlines.atom', 'https://api.theregister.com/headlines.atom'],
  ['https://github.com/example/repo/releases/download/v1/asset', 'https://release-assets.githubusercontent.com/asset'],
])('reviewed redirect from %s remains allowed', async (url, target) => {
  const inner = new FakeHttp()
    .on('GET', /^https:\/\//, request => request.url === url
      ? makeResponse(302, '', { location: target }) : makeResponse(200, 'ok'));
  expect((await createGuardedHttp(inner, { rules: EGRESS_RULES }).request({ method: 'GET', url })).text).toBe('ok');
  expect(inner.calls.map(call => call.url)).toEqual([url, target]);
});

test.each(['release', 'notify', 'user'])('feed redirects cannot switch to owner %s', async owner => {
  const rules = [
    { host: 'first.example.com', owner: 'feed', purpose: 'feed request' },
    { host: 'second.example.com', owner, purpose: 'other request' },
  ];
  const inner = new FakeHttp().on('GET', /first\.example\.com/, () => makeResponse(302, '', { location: 'https://second.example.com/target' }));
  await expect(createGuardedHttp(inner, { rules }).request({ method: 'GET', url: 'https://first.example.com/start' })).rejects.toBeInstanceOf(EgressBlockedError);
  expect(inner.calls).toHaveLength(1);
});
