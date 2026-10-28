// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { registerScreensB } from '../../../src/dashboard/client/screens/b.js';
import { createRouter, type DashboardRouter } from '../../../src/dashboard/client/router.js';

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), postWithPasskey: vi.fn() }));
vi.mock('../../../src/dashboard/client/api.js', () => api);

const secret = 'fixture-private-value-never-render';
const changes = ['Write the new key to Railway/api:OPENAI_KEY.', 'Keep the old key for 15 minutes.'];
const settings = { graceMinutes: 15, rotateEveryDays: 90, spendCapsUsd: { openrouter: 20 }, digestDay: 'mon', showHints: false };
let fixtures: Record<string, unknown>;
let router: DashboardRouter | undefined;
let outlet: HTMLElement;
const tick = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
const control = (text: string, root: ParentNode = document) => {
  const found = [...root.querySelectorAll('button')].find(node => node.textContent === text);
  if (!found) throw new Error(`Button missing: ${text}`);
  return found;
};
const field = (name: string, root: ParentNode = document) => {
  const found = root.querySelector<HTMLInputElement | HTMLSelectElement>(`[name="${name}"]`);
  if (!found) throw new Error(`Field missing: ${name}`);
  return found;
};
async function open(path: string, readOnly = false) {
  router?.stop(); history.replaceState(null, '', `/#${path}`);
  outlet = document.createElement('main'); document.body.append(outlet);
  router = createRouter(outlet);
  registerScreensB(router, { csrf: 'test-csrf', passkeys: 1, readOnly });
  await router.start(); return outlet;
}
async function accept(label: string) { control(label, document.querySelector('dialog')!).click(); await tick(); }

beforeEach(() => {
  document.body.replaceChildren(); history.replaceState(null, '', '/');
  fixtures = {
    keys: { keys: [{ id: 'key-one', provider: 'openai', hint: 'sk-…abcd', method: 'auto', places: [], value: secret }, { id: 'key-two', provider: 'openrouter', hint: null, method: 'auto', places: [] }] },
    rotations: { active: [] },
    autopilot: { state: 'armed', reasons: [], plan: { id: 'armed-one', keys: 2, hosts: ['railway', 'fly'], expiresAt: '2027-01-25T00:00:00Z', graceMinutes: 15 }, waves: [{ id: 'wave-one', incident: 'Railway advisory', status: 'grace-pending', deadline: '2027-01-01T00:00:00Z' }], lastNotificationAt: null, needsRefresh: false },
    'autopilot/eligibility': { eligible: [{ id: 'key-one', provider: 'openai', hint: 'sk-…abcd', needsAdoption: false }, { id: 'key-two', provider: 'openrouter', hint: null, needsAdoption: true }], ineligible: [{ id: 'manual-key', hint: null, reason: 'Rotate this key by hand.' }], lastDrillAt: new Date().toISOString() },
    activity: { verify: { ok: true }, entries: [{ at: '2026-10-27T12:00:00Z', kind: 'verified', summary: 'Verified the new key.', value: secret }] },
    notifications: { channels: [{ id: 'channel-one', kind: 'telegram', label: 'My phone', lastSuccessAt: null }], deviceKeyId: 'device-one' },
    approvals: { pending: [{ id: 'approval-one', kind: 'rotate', summary: 'Rotate one key.', changes, reviewHash: 'review-hash-one', createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString(), source: 'autopilot' }] },
    settings,
  };
  api.get.mockReset().mockImplementation(async route => structuredClone(fixtures[route]));
  api.post.mockReset().mockImplementation(async route => {
    if (route === 'rotate/preview') return { planId: 'plan-one', planHash: 'hash-one', changes, steps: [{ clusterId: 'key-one', hint: 'sk-…abcd', method: 'auto', services: ['Railway/api'] }], warnings: [] };
    if (route === 'card') return { svg: '<svg xmlns="http://www.w3.org/2000/svg"><title>Readiness</title></svg>', score: 80 };
    if (route === 'timeline') return { events: [{ at: '2026-10-27T12:00:00Z', kind: 'verified', summary: 'Verified the new key.' }], markdown: '# Timeline\n\nVerified the new key.\n' };
    if (route === 'drill') return { score: 80, reasons: ['Two keys are ready.'], elapsedMs: 20 };
    if (route === 'notifications/verify') return { valid: true, message: 'Message signature verified.' };
    return { state: 'disarmed' };
  });
  api.postWithPasskey.mockReset().mockImplementation(async route => {
    if (route === 'settings/update') return settings;
    if (route === 'notifications/test') return { delivered: ['channel-one'], failed: [] };
    if (route === 'autopilot/arm') return { planId: 'armed-two', expiresAt: '2027-01-25T00:00:00Z', refused: [] };
    if (route === 'rotation/undo') return { restored: ['key-one'], unavailable: [] };
    return { report: { status: 'grace-pending' }, result: 'Approved.', dismissed: true, removed: true, id: 'new-channel' };
  });
  vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:card-test');
  vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
});
afterEach(async () => {
  router?.stop(); router = undefined; document.body.replaceChildren(); await tick();
  vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals();
});

describe('rotation screen', () => {
  it('uses provider display names in key choices', async () => {
    await open('rotate');
    expect(field('key-one').closest('label')?.textContent).toContain('OpenAI');
    expect(field('key-two').closest('label')?.textContent).toContain('OpenRouter');
  });
  it('preselects the key from the hash and confirms the exact preview before the passkey', async () => {
    await open('rotate?key=key-one');
    expect(field('key-one').checked).toBe(true);
    control('Preview').click(); await tick();
    expect(api.post).toHaveBeenCalledWith('rotate/preview', { clusterIds: ['key-one'] });
    expect([...document.querySelectorAll('dialog li')].map(item => item.textContent)).toEqual(changes);
    expect(api.postWithPasskey).not.toHaveBeenCalled();
    await accept('Rotate 1 key');
    expect(api.postWithPasskey).toHaveBeenCalledWith('rotate/execute', { planId: 'plan-one', planHash: 'hash-one' });
  });
  it('cancels without executing and can run a drill', async () => {
    await open('rotate?key=key-one'); control('Preview').click(); await tick(); await accept('Cancel');
    expect(api.postWithPasskey).not.toHaveBeenCalled();
    control('Run a drill').click(); await tick(); expect(api.post).toHaveBeenCalledWith('drill', {});
    expect(outlet.textContent).toContain('80');
  });
  it('allows a read-only preview without offering execution', async () => {
    await open('rotate?key=key-one', true); expect(control('Preview').disabled).toBe(false);
    control('Preview').click(); await tick(); expect(api.post).toHaveBeenCalledWith('rotate/preview', { clusterIds: ['key-one'] });
    for (const change of changes) expect(outlet.textContent).toContain(change);
    expect(document.querySelector('dialog')).toBeNull(); expect(api.postWithPasskey).not.toHaveBeenCalled();
  });
  it.each([['Revoke old keys now', 'rotation/finish', { planId: 'plan-one', early: true }], ['Undo', 'rotation/undo', { planId: 'plan-one' }]] as const)('sends %s through the passkey helper', async (label, route, body) => {
    fixtures.rotations = { active: [{ planId: 'plan-one', status: 'grace-pending', startedAt: new Date().toISOString(), deadline: new Date(Date.now() + 900_000).toISOString(), steps: [{ clusterId: 'key-one', hint: null, status: 'verified', warnings: [] }] }] };
    await open('rotate'); expect(outlet.querySelector('svg')).not.toBeNull();
    control(label).click(); await tick(); if (document.querySelector('dialog')) await accept(label);
    expect(api.postWithPasskey).toHaveBeenCalledWith(route, body);
  });
  it('leaves the grace deadline unchanged when Later is selected', async () => {
    fixtures.rotations = { active: [{ planId: 'plan-one', status: 'grace-pending', startedAt: new Date().toISOString(), deadline: new Date(Date.now() + 900_000).toISOString(), steps: [] }] };
    await open('rotate'); control('Later').click(); await tick();
    expect(api.postWithPasskey).not.toHaveBeenCalled(); expect(api.post).not.toHaveBeenCalled();
  });
  it('polls while active and stops after navigating away', async () => {
    vi.useFakeTimers(); fixtures.rotations = { active: [{ planId: 'plan-one', status: 'partial', startedAt: new Date().toISOString(), steps: [] }] };
    await open('rotate'); await tick(); const count = api.get.mock.calls.filter(([route]) => route === 'rotations').length;
    await vi.advanceTimersByTimeAsync(3_000);
    expect(api.get.mock.calls.filter(([route]) => route === 'rotations'), 'One poll after three seconds').toHaveLength(count + 1);
    router!.navigate('settings'); await vi.advanceTimersByTimeAsync(1); await tick();
    const stopped = api.get.mock.calls.filter(([route]) => route === 'rotations').length;
    await vi.advanceTimersByTimeAsync(6_000); expect(api.get.mock.calls.filter(([route]) => route === 'rotations'), 'No polls after navigation').toHaveLength(stopped);
  });
  it('keeps keyboard focus on grace actions when progress is polled', async () => {
    vi.useFakeTimers(); fixtures.rotations = { active: [{ planId: 'plan-one', status: 'grace-pending', startedAt: new Date().toISOString(), deadline: new Date(Date.now() + 900_000).toISOString(), steps: [] }] };
    await open('rotate'); control('Undo').focus(); await tick(); await vi.advanceTimersByTimeAsync(3_000);
    expect(document.activeElement?.textContent).toBe('Undo');
  });
  it('keeps the grace ring static under reduced motion while updating the remaining time', async () => {
    vi.useFakeTimers(); vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: true } as MediaQueryList);
    fixtures.rotations = { active: [{ planId: 'plan-one', status: 'grace-pending', startedAt: new Date().toISOString(), deadline: new Date(Date.now() + 900_000).toISOString(), steps: [] }] };
    await open('rotate'); await tick(); const circle = outlet.querySelector('circle')!; const offset = circle.getAttribute('stroke-dashoffset');
    const before = outlet.querySelector('.b-countdown')?.textContent;
    await vi.advanceTimersByTimeAsync(1_000); expect(circle.getAttribute('stroke-dashoffset')).toBe(offset);
    expect(outlet.querySelector('.b-countdown')?.textContent).not.toBe(before);
  });
  it('cancels a pending confirmation when the router is stopped', async () => {
    await open('rotate?key=key-one'); control('Preview').click(); await tick(); expect(document.querySelector('dialog')).not.toBeNull();
    router!.stop(); await tick(); expect(document.querySelector('dialog')).toBeNull(); expect(api.postWithPasskey).not.toHaveBeenCalled();
  });
  it('keeps grace actions disabled during a pending passkey request across poll updates', async () => {
    vi.useFakeTimers(); const rotation = { planId: 'plan-one', status: 'grace-pending', startedAt: new Date().toISOString(), deadline: new Date(Date.now() + 900_000).toISOString(), steps: [] as object[] };
    fixtures.rotations = { active: [rotation] };
    let finish!: (value: unknown) => void; api.postWithPasskey.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    await open('rotate'); control('Revoke old keys now').click(); await tick(); await accept('Revoke old keys now');
    fixtures.rotations = { active: [{ ...rotation, steps: [{ clusterId: 'key-one', hint: null, status: 'verified', warnings: [] }] }] };
    await vi.advanceTimersByTimeAsync(3_000);
    expect(control('Revoke old keys now').disabled).toBe(true); expect(control('Undo').disabled).toBe(true);
    finish({ report: { status: 'complete' } }); await tick();
  });
});

describe('autopilot screen', () => {
  it('uses provider display names for eligibility and adoption confirmation', async () => {
    await open('autopilot');
    expect(field('key-one').closest('label')?.textContent).toContain('OpenAI');
    expect(field('key-two').closest('label')?.textContent).toContain('OpenRouter');
    const adopt = field('adopt-key-two'); adopt.checked = true; adopt.dispatchEvent(new Event('change', { bubbles: true }));
    control('Arm autopilot').click(); await tick();
    expect(document.querySelector('dialog')?.textContent).toContain('This rotates OpenRouter');
    await accept('Cancel');
  });
  it('shows the armed scope, eligibility reasons and waves', async () => {
    await open('autopilot'); expect(outlet.textContent).toContain('armed for 2 keys');
    expect(outlet.textContent).toContain('Railway'); expect(outlet.textContent).toContain('Fly');
    expect(outlet.textContent).toContain('Needs adoption'); expect(outlet.textContent).toContain('Rotate this key by hand.');
    expect(outlet.textContent).toContain('Railway advisory');
  });
  it('disarms with a one-step confirmation and no passkey in read-only mode', async () => {
    await open('autopilot', true); control('Turn off autopilot').click(); await tick();
    expect(api.post).not.toHaveBeenCalled(); await accept('Turn off autopilot');
    expect(api.post).toHaveBeenCalledWith('autopilot/disarm', {}); expect(api.postWithPasskey).not.toHaveBeenCalled();
    expect(outlet.textContent).toContain('disarmed');
  });
  it('requires a recent drill and explicit adoption choices before arming', async () => {
    fixtures['autopilot/eligibility'] = { ...(fixtures['autopilot/eligibility'] as object), lastDrillAt: null };
    await open('autopilot'); expect(control('Arm autopilot').disabled).toBe(true);
    control('Run a drill').click(); await tick();
    const choose = field('key-one'); choose.checked = true; choose.dispatchEvent(new Event('change', { bubbles: true }));
    const adopt = field('adopt-key-two'); expect(adopt.closest('label')?.textContent).toContain('This rotates the key now so keysentry can rotate it automatically later');
    control('Arm autopilot').click(); await tick(); if (document.querySelector('dialog')) await accept('Arm autopilot');
    expect(api.postWithPasskey).toHaveBeenCalledWith('autopilot/arm', { clusterIds: ['key-one'], adopt: [], graceMinutes: 15, maxServices: 10, validDays: 90 });
  });
  it('leaves autopilot disarmed if an earlier arm request finishes after disarm', async () => {
    let finish!: (value: unknown) => void; api.postWithPasskey.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    await open('autopilot'); const key = field('key-one'); key.checked = true; key.dispatchEvent(new Event('change', { bubbles: true }));
    control('Arm autopilot').click(); await tick(); await accept('Arm autopilot');
    control('Turn off autopilot').click(); await tick(); await accept('Turn off autopilot');
    expect(api.post).toHaveBeenCalledWith('autopilot/disarm', {});
    finish({ planId: 'late-plan', expiresAt: '2027-01-25T00:00:00Z', refused: [] }); await tick();
    expect(api.post.mock.calls.filter(([route]) => route === 'autopilot/disarm')).toHaveLength(2);
    expect(outlet.textContent).toContain('Autopilot is disarmed.');
  });
  it('keeps a pending disarm ahead of new arming after leaving and reopening the screen', async () => {
    let finish!: (value: unknown) => void; api.postWithPasskey.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    await open('autopilot'); const key = field('key-one'); key.checked = true; key.dispatchEvent(new Event('change', { bubbles: true }));
    control('Arm autopilot').click(); await tick(); await accept('Arm autopilot');
    control('Turn off autopilot').click(); await tick(); await accept('Turn off autopilot');
    history.replaceState(null, '', '/#settings'); await router!.refresh();
    history.replaceState(null, '', '/#autopilot'); await router!.refresh();
    const nextKey = field('key-one'); nextKey.checked = true; nextKey.dispatchEvent(new Event('change', { bubbles: true }));
    expect(control('Arm autopilot').disabled).toBe(true);
    expect(control('Turn off autopilot').disabled).toBe(true);
    finish({ planId: 'late-plan', expiresAt: '2027-01-25T00:00:00Z', refused: [] }); await tick();
    expect(outlet.textContent).toContain('Autopilot is disarmed.'); expect(control('Arm autopilot').disabled).toBe(false);
  });
});

describe('activity and approvals', () => {
  it('renders the audit check and downloads the returned timeline Markdown locally', async () => {
    await open('activity'); expect(outlet.textContent).toContain('Audit'); expect(outlet.textContent).toContain('Verified the new key.');
    field('id').value = 'plan-one'; control('Timeline').click(); await tick();
    expect(api.post).toHaveBeenCalledWith('timeline', { id: 'plan-one' });
    const clicks = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    control('Download Markdown').click(); await tick();
    expect(clicks).toHaveBeenCalledOnce(); expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(api.post).toHaveBeenCalledTimes(1);
  });
  it('approves and dismisses with the passkey helper', async () => {
    await open('approvals'); control('Approve').click(); await tick(); if (document.querySelector('dialog')) await accept('Approve');
    expect(api.postWithPasskey).toHaveBeenCalledWith('approvals/approve', { id: 'approval-one', reviewHash: 'review-hash-one' });
    await open('approvals'); control('Dismiss').click(); await tick(); if (document.querySelector('dialog')) await accept('Dismiss');
    expect(api.postWithPasskey).toHaveBeenCalledWith('approvals/dismiss', { id: 'approval-one' });
  });
  it('shows team approval progress and treats a recorded approval as progress, not a failure', async () => {
    const data = fixtures.approvals as { pending: Record<string, unknown>[] };
    data.pending[0]!.quorum = { approvals: 0, required: 2 };
    api.postWithPasskey.mockImplementation(async () => ({ result: 'recorded', approvals: 1, required: 2,
      text: 'Your approval was recorded: 1 of 2 team approvals so far. 1 more approval from a team operator or admin who has not approved yet.' }));
    await open('approvals');
    expect(outlet.textContent).toContain('0 of 2 team approvals so far.');
    control('Approve').click(); await tick(); await accept('Approve');
    expect(outlet.textContent).toContain('Waiting for more team approvals');
    expect(outlet.textContent).toContain('1 of 2 team approvals so far.');
    expect(outlet.textContent).toContain('Approval recorded');
    expect(outlet.textContent).not.toContain('Approved');
    expect(api.postWithPasskey).toHaveBeenCalledTimes(1);
  });
  it('shows expired approvals without usable action controls', async () => {
    fixtures.approvals = { pending: [{ id: 'old', kind: 'rotate', summary: 'Old request.', createdAt: '2020-01-01T00:00:00Z', expiresAt: '2020-01-01T00:10:00Z', source: 'monitor' }] };
    await open('approvals'); expect(outlet.textContent).toContain('Expired');
    expect([...outlet.querySelectorAll('button')].filter(item => !item.disabled && ['Approve', 'Dismiss'].includes(item.textContent!))).toHaveLength(0);
  });
  it('repeats every reviewed change verbatim and binds the approval to its hash', async () => {
    await open('approvals'); control('Approve').click(); await tick();
    expect([...document.querySelectorAll('dialog li')].map(item => item.textContent)).toEqual(changes);
    await accept('Approve');
    expect(api.postWithPasskey).toHaveBeenCalledWith('approvals/approve', { id: 'approval-one', reviewHash: 'review-hash-one' });
  });
  it('distinguishes repeated approval summaries in headings and action names', async () => {
    const data = fixtures.approvals as { pending: Record<string, unknown>[] };
    data.pending.push({ ...data.pending[0], id: 'approval-two' }); await open('approvals');
    const headings = [...outlet.querySelectorAll('section h2')].map(item => item.textContent);
    const labels = [...outlet.querySelectorAll('button')].map(item => item.getAttribute('aria-label'));
    expect(new Set(headings).size).toBe(headings.length); expect(new Set(labels).size).toBe(labels.length);
  });
  it('keeps completed approvals completed after their former deadline', async () => {
    vi.useFakeTimers(); await open('approvals'); control('Approve').click(); await tick(); await accept('Approve');
    await vi.advanceTimersByTimeAsync(601_000); expect(outlet.textContent).toContain('Approved'); expect(outlet.textContent).not.toContain('Expired');
  });
  it('ties a missing timeline identifier to its input', async () => {
    await open('activity'); control('Timeline').click(); await tick();
    expect(field('id').getAttribute('aria-invalid')).toBe('true');
    expect(document.getElementById(field('id').getAttribute('aria-describedby')!)?.textContent).toBe('Enter a plan or wave ID.');
    expect(api.post).not.toHaveBeenCalled();
  });
});

describe('notifications, settings and card', () => {
  it('sends channel credentials only in the passkey request and clears secret fields', async () => {
    let sent: unknown; api.postWithPasskey.mockImplementation(async (route, body) => { sent = structuredClone({ route, body }); return { id: 'new-channel' }; });
    await open('notifications'); expect(outlet.textContent).toContain('My phone');
    field('kind').value = 'telegram'; field('kind').dispatchEvent(new Event('change', { bubbles: true }));
    expect(field('botToken').type).toBe('password');
    expect(field('botToken').autocomplete).toBe('one-time-code'); expect(field('botToken').getAttribute('autocapitalize')).toBe('off');
    expect(field('botToken').getAttribute('spellcheck')).toBe('false'); field('botToken').value = secret; field('chatId').value = '123'; field('label').value = 'My phone';
    control('Add channel').click(); await tick(); if (document.querySelector('dialog')) await accept('Add channel');
    expect(sent).toEqual({ route: 'notifications/add', body: { kind: 'telegram', label: 'My phone', settings: { botToken: secret, chatId: '123' } } });
    expect(api.postWithPasskey.mock.calls[0]?.[1].settings.botToken).toBe('');
    expect(document.body.innerHTML).not.toContain(secret); expect(field('botToken').value).toBe('');
  });
  it('tests, verifies and removes channels using the documented routes', async () => {
    await open('notifications'); control('Test all channels').click(); await tick();
    expect(api.postWithPasskey).toHaveBeenCalledWith('notifications/test', {});
    field('code').value = 'ABCD'; control('Check a message').click(); await tick();
    expect(api.post).toHaveBeenCalledWith('notifications/verify', { code: 'ABCD' }); expect(outlet.textContent).toContain('Message signature verified.');
    control('Remove').click(); await tick(); if (document.querySelector('dialog')) await accept('Remove');
    expect(api.postWithPasskey).toHaveBeenCalledWith('notifications/remove', { id: 'channel-one' });
  });
  it('validates settings numbers before submitting and saves the shape with a passkey', async () => {
    await open('settings'); field('graceMinutes').value = '-1'; control('Save settings').click(); await tick();
    expect(api.postWithPasskey).not.toHaveBeenCalled(); field('graceMinutes').value = '20';
    control('Save settings').click(); await tick(); if (document.querySelector('dialog')) await accept('Save settings');
    expect(api.postWithPasskey).toHaveBeenCalledWith('settings/update', { ...settings, graceMinutes: 20 });
  });
  it('makes table regions focusable and names repeated row actions', async () => {
    fixtures.notifications = { channels: [{ id: 'phone', kind: 'ntfy', label: 'Phone', lastSuccessAt: null }, { id: 'work', kind: 'ntfy', label: 'Work', lastSuccessAt: null }], deviceKeyId: 'device-one' };
    await open('notifications');
    const scroller = outlet.querySelector<HTMLElement>('.table-scroll')!;
    expect(scroller.tabIndex).toBe(0); expect(scroller.getAttribute('aria-label')).toBe('Notification channels');
    expect(control('Remove').getAttribute('aria-label')).toBe('Remove Phone (ntfy)');
    expect([...outlet.querySelectorAll('button[aria-label]')].some(item => item.getAttribute('aria-label') === 'Remove Work (ntfy)')).toBe(true);
  });
  it('distinguishes notification removal controls even when channel labels and kinds match', async () => {
    fixtures.notifications = { channels: [{ id: 'phone-one', kind: 'ntfy', label: 'Phone', lastSuccessAt: null }, { id: 'phone-two', kind: 'ntfy', label: 'Phone', lastSuccessAt: null }], deviceKeyId: 'device-one' };
    await open('notifications'); const labels = [...outlet.querySelectorAll('button')].filter(item => item.textContent === 'Remove').map(item => item.getAttribute('aria-label'));
    expect(labels).toEqual(['Remove Phone (ntfy), phone-one', 'Remove Phone (ntfy), phone-two']);
  });
  it.each(['telegram', 'discord', 'slack', 'ntfy', 'webhook', 'resend', 'smtp'])('marks all %s credentials as one-time secret fields', async kind => {
    await open('notifications'); field('kind').value = kind; field('kind').dispatchEvent(new Event('change', { bubbles: true }));
    const secrets = [...outlet.querySelectorAll<HTMLInputElement>('input[type="password"]')]; expect(secrets.length).toBeGreaterThan(0);
    for (const control of secrets) {
      expect(control.autocomplete).toBe('one-time-code'); expect(control.getAttribute('autocapitalize')).toBe('off'); expect(control.getAttribute('spellcheck')).toBe('false');
    }
  });
  it('ties missing notification fields to inline validation messages', async () => {
    await open('notifications'); control('Add channel').click(); await tick();
    expect(field('botToken').getAttribute('aria-invalid')).toBe('true');
    expect(document.getElementById(field('botToken').getAttribute('aria-describedby')!)?.textContent).toBe('Review this field.');
    expect(api.postWithPasskey).not.toHaveBeenCalled();
  });
  it('offers provider choices and distinguishes spend-cap rows', async () => {
    await open('settings'); control('Add spend cap').click();
    const providers = [...outlet.querySelectorAll<HTMLSelectElement>('select[name="spendCapKey"]')];
    expect(providers).toHaveLength(2); expect(providers[0]!.closest('label')?.querySelector('span')?.textContent).toBe('Provider');
    expect([...providers[0]!.options].some(option => option.value === 'openrouter' && option.textContent === 'OpenRouter')).toBe(true);
    expect(new Set(providers.map(item => item.getAttribute('aria-label'))).size).toBe(2);
    expect(outlet.textContent).not.toContain('Provider or key');
  });
  it('connects validation errors to invalid settings and clears them on editing', async () => {
    await open('settings'); const grace = field('graceMinutes'); grace.value = '-1'; control('Save settings').click(); await tick();
    expect(grace.getAttribute('aria-invalid')).toBe('true');
    expect(document.getElementById(grace.getAttribute('aria-describedby')!)?.textContent).toContain('grace');
    grace.value = '15'; grace.dispatchEvent(new Event('input', { bubbles: true })); expect(grace.getAttribute('aria-invalid')).not.toBe('true');
  });
  it('renders the readiness SVG in a Blob URL img and keeps sharing opt-in', async () => {
    await open('card'); expect(api.post).toHaveBeenCalledWith('card', { platform: false, counts: false });
    expect(outlet.querySelector('img')?.getAttribute('src')).toBe('blob:card-test'); expect(outlet.querySelector('svg')).toBeNull();
    const platform = field('platform'); platform.checked = true; platform.dispatchEvent(new Event('change', { bubbles: true })); await tick();
    expect(api.post).toHaveBeenLastCalledWith('card', { platform: true, counts: false });
    router!.stop(); await tick(); expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:card-test');
  });
  it('copies the card as a PNG through a canvas and the image clipboard API', async () => {
    vi.spyOn(HTMLImageElement.prototype, 'decode').mockResolvedValue();
    const drawImage = vi.fn(); vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue({ drawImage } as unknown as CanvasRenderingContext2D);
    vi.spyOn(HTMLCanvasElement.prototype, 'toBlob').mockImplementation(callback => callback(new Blob(['png'], { type: 'image/png' })));
    let copied: Record<string, Promise<Blob>> | undefined;
    vi.stubGlobal('ClipboardItem', class { constructor(value: Record<string, Promise<Blob>>) { copied = value; } });
    const write = vi.fn(async () => {}); Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { write } });
    await open('card'); control('Copy image').click(); await tick();
    expect(drawImage).toHaveBeenCalledOnce(); expect(HTMLCanvasElement.prototype.toBlob).toHaveBeenCalledWith(expect.any(Function), 'image/png');
    expect((await copied!['image/png'])?.type).toBe('image/png'); expect(write).toHaveBeenCalledOnce();
    expect(outlet.textContent).toContain('copied as a PNG');
  });
  it('offers a plain fallback when copying images is unavailable', async () => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
    await open('card'); control('Copy image').click(); await tick(); expect(outlet.textContent).toMatch(/download.*SVG|Download SVG/);
  });
  it.each([['rotate', 'Choose keys'], ['autopilot', 'Autopilot is armed'], ['activity', 'Audit check passed'], ['notifications', 'My phone'], ['approvals', 'Rotate one key.'], ['settings', 'Grace period'], ['card', 'Readiness 80/100']])('%s renders metadata without a fixture value or injected markup', async (path, content) => {
    await open(path); expect(outlet.textContent).toContain(content);
    expect(document.body.innerHTML).not.toContain(secret); expect([...outlet.querySelectorAll('input')].some(item => item.value.includes(secret))).toBe(false);
    expect(document.querySelector('script, [onclick]')).toBeNull();
  });
  it('does not reflect errors from an API response', async () => {
    api.post.mockRejectedValue(new Error(secret)); await open('activity'); field('id').value = 'plan-one'; control('Timeline').click(); await tick();
    expect(document.body.textContent).not.toContain(secret); expect(outlet.querySelector('[role="status"]')?.textContent).toMatch(/could not|Try again/i);
  });
});
