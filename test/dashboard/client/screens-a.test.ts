// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { DashboardSession } from '../../../src/dashboard/client/api.js';
import { createRouter } from '../../../src/dashboard/client/router.js';
import { disposeComponents } from '../../../src/dashboard/client/components.js';
import { registerScreensA } from '../../../src/dashboard/client/screens/a.js';
import { boot } from '../../../src/dashboard/client/main.js';

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), postWithPasskey: vi.fn(), fetchSession: vi.fn(), registerPasskey: vi.fn() }));
vi.mock('../../../src/dashboard/client/api.js', () => api);

const secret = 'fixture-secret-must-stay-out-of-dom';
const session: DashboardSession = { csrf: 'fixture-csrf', readOnly: false, passkeys: 1 };
function fixtures(): Record<string, unknown> {
  return {
    overview: {
      firstRun: { scannedFiles: 8, scannedCommits: 25, historyComplete: false, elapsedMs: 120,
        findings: [], deployTargets: [{ host: 'railway', evidence: 'railway.json' }, { host: 'fly', evidence: 'fly.toml' }], nextSteps: [] },
      connectedPlatforms: ['railway'], keys: 3, inGitHistory: 1, needsRotation: 2, autopilot: 'off',
      nextSteps: ['Connect a platform.', 'Review your keys.', 'Practise a rotation.'], value: secret,
    },
    keys: { keys: [
      { id: 'key /one?', provider: 'openai', tier: 'ai', hint: 'sk-proj…ABCD', method: 'auto',
        places: [{ label: 'API production', host: 'railway', variable: 'OPENAI_API_KEY', writeOnly: false }, { label: 'Build workflow', host: 'github-actions', variable: 'AI_KEY', writeOnly: true }],
        inGitHistory: true, ageDays: 41, rotateBy: '2026-12-01', armed: false, state: 'stop', stateText: 'In git history', value: secret },
      { id: 'key-two', provider: 'openrouter', tier: 'ai', hint: 'sk-or…f00d', method: 'auto',
        places: [{ label: 'Web preview', host: 'vercel', variable: 'OPENROUTER_API_KEY', writeOnly: false }],
        inGitHistory: false, ageDays: 3, armed: true, state: 'ok', stateText: 'Armed', value: secret },
      { id: 'key-three', provider: 'stripe', tier: 'payments', hint: null, method: 'guided', places: [],
        inGitHistory: false, armed: false, state: 'attention', stateText: 'Rotate by hand', value: secret },
    ] },
    platforms: { platforms: [
      { host: 'railway', name: 'Railway', connected: true, source: 'vault', roles: ['read', 'write'],
        tokens: [
          { name: 'RAILWAY_TOKEN', canReadValues: true, canWrite: true, scope: 'Account', recommended: false, howToCreate: 'https://railway.com/account/tokens', source: 'Railway account token documentation' },
          { name: 'RAILWAY_PROJECT_TOKEN', canReadValues: true, canWrite: true, scope: 'One project', recommended: true, howToCreate: 'https://railway.com/project/tokens', source: 'Railway project token documentation' },
        ], keysentryUses: { scan: 'read variables in the selected project', rotate: 'write approved replacement keys and redeploy' }, value: secret },
      { host: 'fly', name: 'Fly', connected: false, roles: ['write'],
        tokens: [{ name: 'FLY_API_TOKEN', canReadValues: false, canWrite: true, scope: 'One app', recommended: true, howToCreate: 'https://fly.io/docs/tokens/', source: 'Fly token documentation' }],
        keysentryUses: { scan: 'list secret names', rotate: 'write approved replacements' } },
    ] },
    access: { items: [
      { area: 'Token permissions', status: 'warn', title: 'Railway token', detail: 'This token can read and write variables.', fix: 'Use a project token for a narrower scope.', value: secret },
      { area: 'Vault', status: 'ok', title: 'OS vault', detail: 'Tokens are stored in the OS vault.' },
      { area: 'Token permissions', status: 'info', title: 'Fly token', detail: 'Fly values are write-only.' },
      { area: 'Network', status: 'fail', title: 'Custom host', detail: 'A host was refused.', fix: 'Review your allowed hosts.' },
    ] },
    network: {
      allowed: [
        { host: 'api.openai.com', purpose: 'Provider API', source: 'built in', value: secret },
        { host: 'api.vercel.com', purpose: 'Platform API', source: 'built in' },
        { host: 'check.example.com', purpose: 'Provider API', source: 'added by you in keysentry.yaml' },
        { host: 'env.example.com', purpose: 'Health check', source: 'added by an environment variable' },
      ], receipt: [{ host: 'api.openai.com', purpose: 'Provider API', count: 7, blocked: 1, lastAt: '2026-10-27T10:00:00Z', value: secret }],
    },
  };
}

let data: Record<string, unknown>;
let routers: ReturnType<typeof createRouter>[];
async function open(path: string, readOnly = false): Promise<HTMLElement> {
  location.hash = `#/${path}`;
  const outlet = document.createElement('main'); document.body.append(outlet);
  const router = createRouter(outlet); registerScreensA(router, { ...session, readOnly }); routers.push(router);
  await router.start(); return outlet;
}
function clickText(root: ParentNode, text: string): void {
  const target = [...root.querySelectorAll<HTMLButtonElement>('button')].find(control => control.textContent === text);
  expect(target, `button ${text}`).toBeDefined(); target!.click();
}
function keydown(element: Element, key: string): void { element.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true })); }
function submit(form: HTMLFormElement): void { form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); }
function fill(form: HTMLFormElement, name: string, value: string): HTMLInputElement {
  const field = form.querySelector<HTMLInputElement>(`[name="${name}"]`)!; field.value = value; return field;
}

beforeEach(() => {
  vi.resetAllMocks(); data = fixtures(); routers = []; document.body.replaceChildren(); location.hash = '#/home';
  api.get.mockImplementation(async route => data[route]); api.fetchSession.mockResolvedValue({ ...session });
  api.postWithPasskey.mockResolvedValue({ stored: true });
});
afterEach(() => { for (const router of routers) router.stop(); disposeComponents(document.body); document.body.replaceChildren(); vi.useRealTimers(); });

describe('Task 6a dashboard screens', () => {
  it('renders first-run sentences, deployment evidence, ordered next steps and screen links', async () => {
    const page = await open('home');
    expect(page.textContent).toContain('3 keys'); expect(page.textContent).toContain('1 key');
    expect(page.textContent).toContain('git history'); expect(page.textContent).toContain('Railway'); expect(page.textContent).toContain('Fly');
    expect(page.textContent).toContain('railway.json'); expect(page.textContent).toContain('25 commits'); expect(page.textContent).toContain('incomplete');
    expect([...page.querySelectorAll('ol li')].map(item => item.textContent)).toEqual(['Connect a platform.', 'Review your keys.', 'Practise a rotation.']);
    for (const route of ['keys', 'connect', 'access', 'network']) expect(page.querySelector(`a[href="#/${route}"]`)).not.toBeNull();
  });

  it('shows the project-folder invitation when there is no scan', async () => {
    data.overview = { firstRun: null, connectedPlatforms: [], keys: 0, inGitHistory: 0, needsRotation: 0, autopilot: 'off', nextSteps: [] };
    const page = await open('home'); expect(page.textContent).toContain('Run keysentry in your project folder to see your keys.');
  });

  it('renders key tags and opens a labelled non-modal panel with every place and action', async () => {
    const page = await open('keys'); expect(page.querySelectorAll('.key-tag')).toHaveLength(3);
    expect(page.querySelector('.key-tag')!.textContent).toContain('2 places'); expect(page.querySelector('.key-tag')!.textContent).toContain('41 days');
    page.querySelector<HTMLButtonElement>('.key-tag')!.click();
    const panel = page.querySelector<HTMLElement>('[role="dialog"]')!;
    expect(panel).not.toBeNull(); expect(panel.getAttribute('aria-modal')).not.toBe('true');
    expect(document.getElementById(panel.getAttribute('aria-labelledby')!)?.textContent).toContain('OpenAI');
    for (const text of ['API production', 'Build workflow', 'OPENAI_API_KEY', 'AI_KEY', 'Readable', 'Write-only', 'In git history', '2026-12-01']) expect(panel.textContent).toContain(text);
    const rotate = [...panel.querySelectorAll('a')].find(link => link.textContent === 'Rotate this key')!;
    expect(rotate.hash).toBe('#/rotate?key=key%20%2Fone%3F'); expect(panel.textContent).toContain('Reveal'); expect(api.postWithPasskey).not.toHaveBeenCalled();
  });

  it('moves focus with all arrow keys, opens with Enter and closes with Escape to its tag', async () => {
    const page = await open('keys'); const tags = [...page.querySelectorAll<HTMLButtonElement>('.key-tag')];
    expect(tags.map(tag => tag.tabIndex)).toEqual([0, -1, -1]); tags[0]!.focus();
    keydown(tags[0]!, 'ArrowRight'); expect(document.activeElement).toBe(tags[1]);
    keydown(tags[1]!, 'ArrowDown'); expect(document.activeElement).toBe(tags[2]);
    keydown(tags[2]!, 'ArrowLeft'); expect(document.activeElement).toBe(tags[1]);
    keydown(tags[1]!, 'ArrowUp'); expect(document.activeElement).toBe(tags[0]);
    keydown(tags[0]!, 'Enter'); const panel = page.querySelector<HTMLElement>('[role="dialog"]')!;
    expect(panel.contains(document.activeElement)).toBe(true); keydown(document.activeElement!, 'Escape');
    expect(page.querySelector('[role="dialog"]')).toBeNull(); expect(document.activeElement).toBe(tags[0]);
  });

  it('combines state, platform and provider toggles and can clear them', async () => {
    const page = await open('keys');
    const group = (name: string) => [...page.querySelectorAll('fieldset')].find(field => field.querySelector('legend')?.textContent === name)!;
    clickText(group('State'), 'In git history'); clickText(group('Platform'), 'Railway'); clickText(group('Provider'), 'OpenAI');
    expect(page.querySelectorAll('.key-tag')).toHaveLength(1); expect(group('Provider').querySelector('[aria-pressed="true"]')?.textContent).toBe('OpenAI');
    clickText(group('Platform'), 'Vercel'); expect(page.querySelectorAll('.key-tag')).toHaveLength(1);
    clickText(group('Platform'), 'Railway'); expect(page.textContent).toContain('No keys match these filters.');
    clickText(page, 'Clear filters'); expect(page.querySelectorAll('.key-tag')).toHaveLength(3);
  });

  it('keeps the key cabinet visible while the Filter disclosure starts closed', async () => {
    const page = await open('keys');
    const filters = page.querySelector<HTMLDetailsElement>('details');
    expect(filters).not.toBeNull(); expect(filters!.open).toBe(false);
    expect(filters!.querySelector('summary')?.textContent).toBe('Filter');
    expect(filters!.querySelectorAll('fieldset')).toHaveLength(3);
    expect(filters!.contains(page.querySelector('.screen-a-cabinet'))).toBe(false);
    expect(page.querySelectorAll('.key-tag')).toHaveLength(3);
  });

  it('reveals only after confirmation, and scrubs a retained panel on close', async () => {
    api.postWithPasskey.mockResolvedValue({ value: secret });
    const page = await open('keys'); page.querySelector<HTMLButtonElement>('.key-tag')!.click();
    const panel = page.querySelector<HTMLElement>('[role="dialog"]')!; clickText(panel, 'Reveal');
    expect(api.postWithPasskey).not.toHaveBeenCalled(); clickText(document.querySelector('dialog')!, 'Reveal value');
    await vi.waitFor(() => expect(panel.querySelector('.masked-value-output')?.textContent).toBe(secret));
    expect(api.postWithPasskey).toHaveBeenCalledWith('reveal', { clusterId: 'key /one?' });
    expect(page.textContent!.replace(panel.querySelector('.masked-value-output')!.textContent!, '')).not.toContain(secret);
    clickText(panel, 'Close'); expect(panel.textContent).not.toContain(secret); expect(page.textContent).not.toContain(secret);
  });

  it('cancels a pending reveal on tag selection and ignores its late value', async () => {
    let complete!: (value: { value: string }) => void;
    api.postWithPasskey.mockImplementation(() => new Promise(resolve => { complete = resolve; }));
    const page = await open('keys'); const tags = [...page.querySelectorAll<HTMLButtonElement>('.key-tag')]; tags[0]!.click();
    const panel = page.querySelector<HTMLElement>('[role="dialog"]')!; clickText(panel, 'Reveal'); clickText(document.querySelector('dialog')!, 'Reveal value');
    await vi.waitFor(() => expect(api.postWithPasskey).toHaveBeenCalled()); tags[1]!.click();
    const response = { value: secret }; complete(response);
    await vi.waitFor(() => expect(response.value).toBe('')); expect(panel.textContent).not.toContain(secret); expect(page.textContent).not.toContain(secret);
  });

  it('keeps Reveal visibly unavailable for a key with only write-only places', async () => {
    const response = data.keys as { keys: { places: { writeOnly: boolean }[] }[] };
    response.keys[0]!.places.forEach(place => { place.writeOnly = true; });
    const page = await open('keys'); page.querySelector<HTMLButtonElement>('.key-tag')!.click();
    const panel = page.querySelector('[role="dialog"]')!;
    const reveal = [...panel.querySelectorAll<HTMLButtonElement>('button')].find(control => control.textContent === 'Reveal');
    expect(reveal).toBeDefined(); expect(reveal!.disabled).toBe(true); expect(panel.textContent).toContain('no readable place');
  });

  it('closes the details and its pending reveal confirmation when filters change', async () => {
    const page = await open('keys'); page.querySelector<HTMLButtonElement>('.key-tag')!.click();
    const panel = page.querySelector('[role="dialog"]')!; clickText(panel, 'Reveal');
    expect(document.querySelector('dialog')).not.toBeNull(); clickText(page, 'Clear filters');
    expect(page.querySelector('[role="dialog"]')).toBeNull(); expect(document.querySelector('dialog')).toBeNull(); expect(api.postWithPasskey).not.toHaveBeenCalled();
  });

  it('renders each platform, token source and narrowest token first with accurate capability copy', async () => {
    const page = await open('connect');
    const platforms = [...page.querySelectorAll<HTMLElement>('[data-platform]')]; expect(platforms).toHaveLength(2);
    expect(platforms[0]!.textContent).toContain('Connected'); expect(platforms[0]!.textContent).toContain('Stored in the vault');
    expect(platforms[1]!.textContent).toContain('Not connected'); expect(platforms[1]!.textContent).toContain('No token stored');
    expect(platforms[0]!.querySelector('h3')?.textContent).toContain('RAILWAY_PROJECT_TOKEN');
    expect(platforms[0]!.textContent).toContain('This token can'); expect(platforms[0]!.textContent).toContain('keysentry will only');
    expect(platforms[1]!.textContent).toContain('cannot read back');
    expect(platforms[0]!.querySelector<HTMLAnchorElement>('a')?.textContent).toBe('How to create it');
    expect(platforms[0]!.querySelector<HTMLAnchorElement>('a')?.href).toBe('https://railway.com/project/tokens');
    expect(platforms[0]!.querySelector<HTMLSelectElement>('[name="role"]')?.value).toBe('read');
  });

  it('stores a token only through the passkey helper and immediately clears the field and request object', async () => {
    let complete!: (value: { stored: true }) => void; let requestBody!: { name: string; role: string; value: string };
    let sent: unknown;
    api.postWithPasskey.mockImplementation((_route, body) => { sent = { ...body }; requestBody = body; return new Promise(resolve => { complete = resolve; }); });
    const page = await open('connect'); const form = page.querySelector<HTMLFormElement>('form')!;
    fill(form, 'name', 'RAILWAY_PROJECT_TOKEN'); fill(form, 'role', 'read'); const field = fill(form, 'value', secret);
    expect(field.type).toBe('password'); expect(field.autocomplete).toBe('off'); submit(form);
    expect(field.value).toBe(''); expect(requestBody.value).toBe(''); expect(sent).toEqual({ name: 'RAILWAY_PROJECT_TOKEN', role: 'read', value: secret });
    expect(api.postWithPasskey).toHaveBeenCalledTimes(1); expect(api.postWithPasskey.mock.calls[0]![0]).toBe('vault/store'); expect(api.post).not.toHaveBeenCalled();
    expect(form.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled).toBe(true); submit(form); expect(api.postWithPasskey).toHaveBeenCalledTimes(1);
    complete({ stored: true }); await vi.waitFor(() => expect(page.textContent).toContain('Stored token.')); expect(page.outerHTML).not.toContain(secret);
  });

  it('does not echo a token-bearing error and keeps the input cleared after refusal', async () => {
    api.postWithPasskey.mockRejectedValue(new Error(secret)); const page = await open('connect'); const form = page.querySelector<HTMLFormElement>('form')!;
    const field = fill(form, 'value', secret); submit(form);
    await vi.waitFor(() => expect(form.textContent).toContain('Token was not stored.')); expect(field.value).toBe(''); expect(page.outerHTML).not.toContain(secret);
  });

  it('does not turn an unsafe how-to link into an executable URL', async () => {
    const platforms = data.platforms as { platforms: { tokens: { howToCreate: string }[] }[] };
    platforms.platforms[0]!.tokens[1]!.howToCreate = 'javascript:alert(1)';
    const page = await open('connect'); expect(page.querySelector('a[href^="javascript:"]')).toBeNull();
  });

  it('groups doctor checks by area and shows status words, details and fixes', async () => {
    const page = await open('access'); expect([...page.querySelectorAll('h2')].map(heading => heading.textContent)).toEqual(['Token permissions', 'Vault', 'Network']);
    for (const text of ['Railway token', 'Fly token', 'Needs attention', 'Complete', 'Information', 'Stopped', 'Use a project token', 'Review your allowed hosts.']) expect(page.textContent).toContain(text);
  });

  it('groups allowed hosts by purpose with source and renders the receipt table', async () => {
    const page = await open('network'); const headings = [...page.querySelectorAll('h2')].map(heading => heading.textContent);
    expect(headings.filter(text => text === 'Provider API')).toHaveLength(1);
    for (const text of ['api.openai.com', 'check.example.com', 'built in', 'added by you in keysentry.yaml', 'added by an environment variable']) expect(page.textContent).toContain(text);
    const receipt = [...page.querySelectorAll('table')].find(table => table.caption?.textContent === 'Network receipt')!;
    expect(receipt).toBeDefined(); expect([...receipt.tHead!.querySelectorAll('th')].map(cell => cell.textContent)).toEqual(['Host', 'Purpose', 'Requests', 'Blocked', 'Last contacted']);
    expect(receipt.querySelector('tbody tr')!.textContent).toContain('7'); expect(receipt.textContent).toContain('2026-10-27T10:00:00Z');
  });

  it.each(['home', 'keys', 'connect', 'access', 'network'])('%s ignores unexpected value fields in fixture responses', async path => {
    const page = await open(path); expect(api.get).toHaveBeenCalledWith(path === 'home' ? 'overview' : path === 'connect' ? 'platforms' : path);
    expect(page.textContent).not.toContain('This page could not be opened.'); expect(page.outerHTML).not.toContain(secret); expect(api.postWithPasskey).not.toHaveBeenCalled();
  });

  it('keeps token storage and reveal unavailable in a read-only session', async () => {
    const connect = await open('connect', true); const form = connect.querySelector<HTMLFormElement>('form')!;
    expect(form.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled).toBe(true);
    fill(form, 'value', secret); submit(form); expect(form.querySelector<HTMLInputElement>('[name="value"]')?.value).toBe('');
    const page = await open('keys', true); page.querySelector<HTMLButtonElement>('.key-tag')!.click();
    const reveal = [...page.querySelectorAll<HTMLButtonElement>('button')].find(control => control.textContent === 'Reveal')!; expect(reveal.disabled).toBe(true);
    reveal.click(); expect(api.postWithPasskey).not.toHaveBeenCalled();
  });

  it('places the exact read-only notice below the page heading after every navigation', async () => {
    api.fetchSession.mockResolvedValue({ ...session, readOnly: true }); const root = document.createElement('div'); document.body.append(root);
    const app = await boot(root); routers.push(app.router);
    const check = () => {
      const main = root.querySelector('main')!; const notice = main.querySelector('.read-only-notice'); expect(notice).not.toBeNull(); expect(main.querySelector('h1')?.nextElementSibling).toBe(notice);
      expect(notice!.textContent).toContain('This dashboard is read-only because it was opened by an automated tool or with --read-only. To make changes, run keysentry ui in your own terminal.');
    };
    await vi.waitFor(check); app.router.navigate('network'); await vi.waitFor(() => expect(root.querySelector('h1')?.textContent).toBe('Network')); check(); app.destroy();
  });

  it('keeps passkey enrollment below the page heading across navigation', async () => {
    api.fetchSession.mockResolvedValue({ ...session, passkeys: 0 });
    api.registerPasskey.mockResolvedValue(undefined);
    const root = document.createElement('div'); document.body.append(root);
    const app = await boot(root); routers.push(app.router);
    const check = () => {
      const main = root.querySelector('main')!;
      expect(main.querySelector('h1')?.nextElementSibling?.textContent).toContain('Register a passkey');
      expect(main.querySelector('button')?.textContent).toBe('Register passkey');
    };
    check(); app.router.navigate('network');
    await vi.waitFor(() => expect(root.querySelector('h1')?.textContent).toBe('Network')); check();
    clickText(root, 'Register passkey');
    await vi.waitFor(() => expect(root.textContent).toContain('Passkey registered'));
    expect(app.session.passkeys).toBe(1); app.destroy();
  });

  it('offers a retry when a screen request fails without reflecting its error', async () => {
    api.get.mockRejectedValueOnce(new Error(secret)); const page = await open('keys');
    expect(page.textContent).toContain('This page could not be opened.'); expect(page.textContent).not.toContain(secret);
    clickText(page, 'Try again'); await vi.waitFor(() => expect(page.querySelectorAll('.key-tag')).toHaveLength(3));
  });
});
