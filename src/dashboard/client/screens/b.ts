import type { DashboardSession } from '../api.js';
import type { DashboardRouter } from '../router.js';
import { renderRotate } from './rotate.js';
import { renderAutopilot } from './autopilot.js';
import { renderActivity } from './activity.js';
import { renderNotifications } from './notifications.js';
import { renderApprovals } from './approvals.js';
import { renderSettings } from './settings.js';
import { renderCard } from './card.js';
import { disposeScreen } from './components-b.js';

export function registerScreensB(router: DashboardRouter, session: DashboardSession): void {
  let generation = 0; let current: HTMLElement | undefined;
  // The existing shell exposes stop(), but no general screen disposal hook.
  const stop = router.stop.bind(router);
  router.stop = () => { ++generation; if (current) disposeScreen(current); current = undefined; stop(); };
  const navigate = router.navigate.bind(router);
  router.navigate = path => { ++generation; if (current) disposeScreen(current); current = undefined; navigate(path); };
  const screens = [
    ['rotate', 'Rotate keys', renderRotate], ['autopilot', 'Autopilot', renderAutopilot],
    ['activity', 'Activity', renderActivity], ['notifications', 'Notifications', renderNotifications],
    ['approvals', 'Approvals', renderApprovals], ['settings', 'Settings', renderSettings], ['card', 'Readiness card', renderCard],
  ] as const;
  for (const [path, title, render] of screens) router.register(path, { title, async render() {
    const renderGeneration = ++generation; const hash = location.hash;
    if (current) disposeScreen(current); current = undefined;
    const content = await render(session);
    if (renderGeneration !== generation || hash !== location.hash) disposeScreen(content); else current = content;
    return content;
  } });
}
