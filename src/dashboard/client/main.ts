import { fetchSession, passkeyRegistrationNotice } from './api.js';
import type { DashboardSession } from './api.js';
import { emptyState, notice } from './components.js';
import { createRouter } from './router.js';
import { registerScreensA } from './screens/a.js';
import { registerScreensB } from './screens/b.js';
import type { DashboardRouter } from './router.js';

export interface DashboardApp { session: DashboardSession; router: DashboardRouter; destroy(): void }

const pages = [
  ['home', 'Overview', 'Overview'], ['keys', 'Keys', 'Your keys'], ['connect', 'Connect', 'Connect a platform'],
  ['rotate', 'Rotate', 'Rotate keys'], ['autopilot', 'Autopilot', 'Autopilot'], ['activity', 'Activity', 'Activity'],
  ['notifications', 'Notifications', 'Notifications'], ['approvals', 'Approvals', 'Approvals'], ['settings', 'Settings', 'Settings'],
  ['card', 'Readiness card', 'Readiness card'],
] as const;

function link(text: string, route: string): HTMLAnchorElement {
  const anchor = document.createElement('a'); anchor.href = `#/${route}`; anchor.textContent = text; return anchor;
}

export async function boot(root: HTMLElement): Promise<DashboardApp> {
  const session = await fetchSession();
  const shell = document.createElement('div'); shell.className = 'app-shell';
  const skip = document.createElement('a'); skip.className = 'skip-link'; skip.href = '#main-content'; skip.textContent = 'Skip to content';
  const header = document.createElement('header'); header.className = 'app-header';
  const brand = link('keysentry', 'home'); brand.className = 'app-brand';
  const headerLinks = document.createElement('div'); headerLinks.className = 'app-header-links'; headerLinks.append(link('What keysentry can access', 'access'), link('Network', 'network'));
  header.append(brand, headerLinks);
  const body = document.createElement('div'); body.className = 'app-body';
  const nav = document.createElement('nav'); nav.className = 'app-nav'; nav.setAttribute('aria-label', 'Main navigation');
  for (const [route, label] of pages) nav.append(link(label, route));
  const content = document.createElement('div');
  const main = document.createElement('main'); main.className = 'page'; main.id = 'main-content';
  skip.addEventListener('click', event => { event.preventDefault(); main.querySelector<HTMLElement>('h1')?.focus(); });
  let sessionNotice: HTMLElement | undefined;
  if (session.readOnly) {
    const readOnly = notice('info', 'Read-only', 'This dashboard is read-only because it was opened by an automated tool or with --read-only. To make changes, run keysentry ui in your own terminal.'); readOnly.classList.add('read-only-notice');
    sessionNotice = readOnly;
  }
  if (session.passkeys === 0) {
    if (sessionNotice) {
      const instruction = document.createElement('p'); instruction.textContent = passkeyRegistrationNotice;
      sessionNotice.append(instruction);
    } else sessionNotice = notice('info', 'Register a passkey', passkeyRegistrationNotice);
  }
  content.append(main); body.append(nav, content); shell.append(skip, header, body); root.replaceChildren(shell);
  const router = createRouter(main, {}, route => {
    // The router replaces the page on navigation; keep session guidance inside its padded column.
    if (sessionNotice) main.querySelector('h1')?.after(sessionNotice);
    for (const anchor of shell.querySelectorAll<HTMLAnchorElement>('a[href^="#/"]')) {
      if (anchor.hash === `#/${route}`) anchor.setAttribute('aria-current', 'page'); else anchor.removeAttribute('aria-current');
    }
  });
  for (const [path, , title] of [...pages, ['access', 'Access', 'What keysentry can access'], ['network', 'Network', 'Network']] as const) {
    router.register(path, { title, render: () => emptyState(path === 'home' ? 'Start with your keys to review the next steps for this project.' : 'Return to the overview to choose the next step for this project.', { label: path === 'home' ? 'See your keys' : 'Open overview', onClick: () => router.navigate(path === 'home' ? 'keys' : 'home') }) });
  }
  // Real screens replace the placeholders above (tasks 6a and 6b each own one registration module).
  registerScreensA(router, session);
  registerScreensB(router, session);
  await router.start();
  return { session, router, destroy() { router.stop(); root.replaceChildren(); } };
}

function start(): void {
  const root = document.getElementById('app');
  if (root) void boot(root).catch(() => { root.replaceChildren(notice('info', 'Open keysentry again', 'Open keysentry from your terminal with keysentry ui.')); });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true }); else start();
