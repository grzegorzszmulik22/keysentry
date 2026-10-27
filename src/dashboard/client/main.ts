import { fetchSession, registerPasskey } from './api.js';
import type { DashboardSession } from './api.js';
import { button, emptyState, notice } from './components.js';
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
  if (session.readOnly) {
    const readOnly = notice('info', 'Read-only', 'This dashboard is read-only because it was opened by an automated tool or with --read-only. To make changes, run keysentry ui in your own terminal.'); readOnly.classList.add('read-only-notice');
    // The router replaces page children on navigation; keep this notice below its heading.
    new MutationObserver(() => {
      const heading = main.querySelector('h1');
      if (heading && heading.nextSibling !== readOnly) heading.after(readOnly);
    }).observe(main, { childList: true });
  } else if (session.passkeys === 0) {
    const enrollment = notice('info', 'Register a passkey', 'Changes require a passkey with user verification. Register one on this device before making a change.');
    const status = document.createElement('p'); status.setAttribute('role', 'status');
    const control = button('Register passkey', () => { control.disabled = true; void registerPasskey().then(() => { session.passkeys++; enrollment.replaceChildren(notice('ok', 'Passkey registered', 'Your passkey will be requested when you choose a change.')); }).catch(() => { status.textContent = 'Passkey registration was not completed. Try again.'; }).finally(() => { control.disabled = false; }); });
    enrollment.append(control, status); content.append(enrollment);
  }
  content.append(main); body.append(nav, content); shell.append(skip, header, body); root.replaceChildren(shell);
  const router = createRouter(main, {}, route => {
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
