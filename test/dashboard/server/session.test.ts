import { describe, expect, it } from 'vitest';
import { createSession } from '../../../src/dashboard/server/session.js';

describe('dashboard session', () => {
  it('exchanges a random single-use token for an independent session and csrf token', () => {
    const sessions = createSession({ idleMs: 900_000, port: () => 42001 });
    expect(Buffer.from(sessions.token, 'base64url')).toHaveLength(32);
    const session = sessions.exchange(sessions.token)!;
    expect(session.id).not.toBe(sessions.token);
    expect(session.csrf).not.toBe(session.id);
    expect(sessions.exchange(sessions.token)).toBeNull();
    expect(sessions.cookieName).toBe('ks_session_42001');
    expect(sessions.authenticate(`ks_session_42001=${session.id}`)?.id).toBe(session.id);
    expect(sessions.authenticate(`ks_session_42001=${session.id}; ks_session_42001=${session.id}`)).toBeNull();
    expect(sessions.authenticate('ks_session_42001=wrong')).toBeNull();
    expect(sessions.authenticate(`ks_session_42001=${'é'.repeat(session.id.length)}`)).toBeNull();
    expect(sessions.authenticate(`ks_session=${session.id}`)).toBeNull();
    expect(sessions.authenticate(`ks_session_42002=${session.id}`)).toBeNull();
  });

  it('expires the login token inclusively at two minutes', () => {
    let now = 0;
    const sessions = createSession({ idleMs: 900_000, now: () => now, port: () => 42001 });
    now = 120_000;
    expect(sessions.exchange(sessions.token)).toBeNull();
  });

  it('expires a session after idle time and clears it when closed', () => {
    let now = 0;
    const sessions = createSession({ idleMs: 100, now: () => now, port: () => 42001 });
    const session = sessions.exchange(sessions.token)!;
    now = 99;
    expect(sessions.authenticate(`ks_session_42001=${session.id}`)).not.toBeNull();
    now = 199;
    expect(sessions.authenticate(`ks_session_42001=${session.id}`)).toBeNull();
    sessions.clear();
    expect(sessions.exchange(sessions.token)).toBeNull();
  });
});
