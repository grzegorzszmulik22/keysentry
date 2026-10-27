import type { DashboardSession } from '../api.js';
import type { DashboardRouter } from '../router.js';
import { renderHome } from './home.js';
import { renderKeys } from './keys.js';
import { renderConnect } from './connect.js';
import { renderAccess } from './access.js';
import { renderNetwork } from './network.js';

export function registerScreensA(router: DashboardRouter, session: DashboardSession): void {
  router.register('home', { title: 'Overview', render: renderHome });
  router.register('keys', { title: 'Your keys', render: () => renderKeys(session) });
  router.register('connect', { title: 'Connect a platform', render: () => renderConnect(session) });
  router.register('access', { title: 'What keysentry can access', render: renderAccess });
  router.register('network', { title: 'Network', render: renderNetwork });
}
