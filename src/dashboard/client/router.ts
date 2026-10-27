import { disposeComponents, emptyState } from './components.js';

export interface DashboardRoute { title: string; render(): Node | Promise<Node> }
export interface DashboardRouter {
  register(path: string, route: DashboardRoute): void;
  start(): Promise<void>;
  stop(): void;
  navigate(path: string): void;
  refresh(): Promise<void>;
}

/** Screen renderers return page content; the router owns the page heading and focus. */
export function createRouter(outlet: HTMLElement, initial: Record<string, DashboardRoute> = {}, onNavigate?: (path: string) => void): DashboardRouter {
  const routes = new Map(Object.entries(initial));
  let generation = 0;
  let started = false;
  let lastPath: string | undefined;
  const path = () => location.hash.replace(/^#\/?/, '').split('?')[0] || 'home';
  const refresh = async (): Promise<void> => {
    const current = ++generation;
    disposeComponents(outlet);
    const selected = path();
    lastPath = selected;
    const route = routes.get(selected);
    const heading = document.createElement('h1'); heading.className = 'page-heading'; heading.tabIndex = -1;
    heading.textContent = route?.title ?? 'Page not found';
    let content: Node;
    try { content = route ? await route.render() : emptyState('Choose a page from the navigation to continue.', { label: 'Open overview', onClick: () => router.navigate('home') }); }
    catch { content = emptyState('This page could not be opened. Try again.', { label: 'Try again', onClick: () => { void refresh(); } }); }
    if (current !== generation) { if (content instanceof Element || content instanceof DocumentFragment) disposeComponents(content); return; }
    outlet.replaceChildren(heading, content);
    document.title = `${heading.textContent} · keysentry`;
    heading.focus();
    onNavigate?.(selected);
  };
  const changed = () => { if (path() !== lastPath) void refresh(); };
  const router: DashboardRouter = {
    register(key, route) { routes.set(key.replace(/^#\/?/, ''), route); },
    async start() { if (!started) { started = true; window.addEventListener('hashchange', changed); await refresh(); } },
    stop() { started = false; generation++; disposeComponents(outlet); window.removeEventListener('hashchange', changed); },
    navigate(key) { const next = key.replace(/^#\/?/, ''); if (path() === next) void refresh(); else location.hash = `#/${next}`; },
    refresh,
  };
  return router;
}
