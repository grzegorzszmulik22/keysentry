import { expect, test } from 'vitest';
import { detectPlatform, ownPlatformIncident } from '../../src/watcher/platform.js';
import type { Incident } from '../../src/types.js';

test.each([
  [{ RAILWAY_ENVIRONMENT: 'production' }, { platform: 'railway', host: 'railway' }],
  [{ FLY_APP_NAME: 'watcher' }, { platform: 'fly', host: 'fly' }],
  [{ RENDER: 'true' }, { platform: 'render', host: 'render' }],
  [{ GITHUB_ACTIONS: 'true' }, { platform: 'github-actions', host: 'github-actions' }],
  [{}, { platform: 'unknown', host: null }],
])('detectPlatform recognises each platform without exposing env values', (env, expected) => {
  expect(detectPlatform(env, { docker: false })).toEqual(expected);
});

test('Docker detection does not override a known host and empty markers do not identify a platform', () => {
  expect(detectPlatform({}, { docker: true })).toEqual({ platform: 'docker', host: null });
  expect(detectPlatform({ RAILWAY_ENVIRONMENT: 'production' }, { docker: true })).toEqual({ platform: 'railway', host: 'railway' });
  expect(detectPlatform({ RAILWAY_ENVIRONMENT: '', GITHUB_ACTIONS: 'false' }, { docker: false })).toEqual({ platform: 'unknown', host: null });
});

test('an incident on the watcher own host is identified for guided rotation', () => {
  const incident: Incident = { id: 'inc-test', host: 'railway', openedAt: '2026-10-27T00:00:00Z', evidence: [], status: 'triggered' };
  expect(ownPlatformIncident(incident, detectPlatform({ RAILWAY_ENVIRONMENT: 'production' }))).toBe(true);
  expect(ownPlatformIncident(incident, detectPlatform({ FLY_APP_NAME: 'watcher' }))).toBe(false);
  expect(ownPlatformIncident(incident, detectPlatform({}, { docker: true }))).toBe(false);
});
