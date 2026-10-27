import { get } from '../api.js';
import type { DashboardSession } from '../api.js';
import { button, disposeComponents, emptyState, keyTag, maskedValue } from '../components.js';
import { element, hostName, providerName, routeLink, scrollTable } from './components-a.js';
import type { KeyView } from './components-a.js';

let panelNumber = 0;

export async function renderKeys(session: DashboardSession): Promise<HTMLElement> {
  const { keys } = await get<{ keys: KeyView[] }>('keys');
  const page = element('div', undefined, 'screen-a keys-screen');
  page.append(element('p', 'Choose a key tag to see every place it lives. Opening a tag does not reveal its value or make a change.'));
  if (!keys.length) {
    page.append(emptyState('Run keysentry in your project folder to see your keys.'));
    page.append(routeLink('Connect a platform', 'connect')); return page;
  }
  const filters = element('div', undefined, 'screen-a-filters');
  const cabinet = element('div', undefined, 'screen-a-cabinet');
  const results = element('p', undefined, 'screen-a-muted'); results.setAttribute('role', 'status');
  const grid = element('div', undefined, 'key-grid'); grid.setAttribute('role', 'group'); grid.setAttribute('aria-label', 'Key cabinet');
  const detail = element('div', undefined, 'screen-a-detail');
  const selected = { state: new Set<string>(), host: new Set<string>(), provider: new Set<string>() };
  let selectedTag: HTMLButtonElement | undefined;
  let tags: HTMLButtonElement[] = [];
  const toggles: { control: HTMLButtonElement; selection: Set<string>; value: string }[] = [];
  const close = (restoreFocus = true) => {
    disposeComponents(detail); detail.replaceChildren();
    selectedTag?.setAttribute('aria-expanded', 'false'); selectedTag?.removeAttribute('aria-controls');
    if (restoreFocus && selectedTag?.isConnected) selectedTag.focus();
    selectedTag = undefined; cabinet.classList.remove('has-detail');
  };
  const focusTag = (index: number) => {
    for (let i = 0; i < tags.length; i++) tags[i]!.tabIndex = i === index ? 0 : -1;
    tags[index]?.focus();
  };
  const open = (key: KeyView, tag: HTMLButtonElement) => {
    close(false); selectedTag = tag; focusTag(tags.indexOf(tag)); tag.setAttribute('aria-expanded', 'true');
    const panel = element('section', undefined, 'screen-a-key-panel'); panel.id = `key-panel-${++panelNumber}`;
    panel.setAttribute('role', 'dialog'); panel.setAttribute('aria-modal', 'false');
    const heading = element('h2', `${providerName(key.provider)} key`); heading.id = `${panel.id}-heading`; heading.tabIndex = -1;
    panel.setAttribute('aria-labelledby', heading.id); tag.setAttribute('aria-controls', panel.id);
    panel.append(heading, element('code', key.hint ?? 'Hint unavailable'), element('p', key.stateText, `screen-a-state state-${key.state}`));
    panel.append(element('p', key.inGitHistory ? 'In git history. Rotate this key even if it has been removed from current files.' : 'Not found in the scanned git history.'));
    panel.append(element('p', key.rotateBy ? `Rotate by ${key.rotateBy}.` : 'No rotate-by date is available.'));
    if (key.places.length) panel.append(scrollTable(['Place', 'Platform', 'Variable', 'Access'], key.places.map(place => [place.label, hostName(place.host), element('code', place.variable), place.writeOnly ? 'Write-only' : 'Readable']), 'Places this key lives'));
    else panel.append(element('p', 'No current places are listed for this key.'));
    panel.append(element('p', 'Review a rotation plan before approving changes. Revealing a readable value requires passkey verification.'));
    const actions = element('div', undefined, 'screen-a-links');
    actions.append(routeLink('Rotate this key', `rotate?key=${encodeURIComponent(key.id)}`), button('Close', () => close(), 'secondary'));
    panel.append(actions);
    const readable = key.places.some(place => !place.writeOnly);
    const value = maskedValue({ route: 'reveal', body: { clusterId: key.id } });
    if (session.readOnly || !readable) { for (const control of value.querySelectorAll<HTMLButtonElement>('button')) control.disabled = true; }
    panel.append(value);
    if (!readable) panel.append(element('p', 'Reveal is unavailable because no readable place is listed for this key.'));
    detail.append(panel); cabinet.classList.add('has-detail'); heading.focus();
  };
  const renderTags = () => {
    close(false);
    const visible = keys.filter(key =>
      (!selected.state.size || selected.state.has(key.stateText)) &&
      (!selected.provider.size || selected.provider.has(key.provider)) &&
      (!selected.host.size || key.places.some(place => selected.host.has(place.host))));
    grid.replaceChildren(); tags = [];
    results.textContent = `Showing ${visible.length} of ${keys.length} keys.`;
    if (!visible.length) grid.append(emptyState('No keys match these filters.'));
    for (const key of visible) {
      const tag = keyTag({ provider: providerName(key.provider), hint: key.hint, state: key.stateText, copies: key.places.length, ageDays: key.ageDays }, () => open(key, tag));
      tag.dataset.state = key.state; tag.setAttribute('aria-haspopup', 'dialog'); tag.setAttribute('aria-expanded', 'false');
      tag.tabIndex = tags.length ? -1 : 0;
      tag.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(key, tag); return; }
        const direction = ({ ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 } as Record<string, number>)[event.key];
        if (direction !== undefined) { event.preventDefault(); focusTag((tags.indexOf(tag) + direction + tags.length) % tags.length); }
        if (event.key === 'Home' || event.key === 'End') { event.preventDefault(); focusTag(event.key === 'Home' ? 0 : tags.length - 1); }
      });
      tags.push(tag); grid.append(tag);
    }
  };
  const filterGroup = (title: string, selection: Set<string>, values: string[], label: (value: string) => string) => {
    const group = element('fieldset', undefined, 'screen-a-filter'); group.append(element('legend', title));
    for (const value of [...new Set(values)]) {
      const control = button(label(value), () => {
        if (selection.has(value)) selection.delete(value); else selection.add(value);
        control.setAttribute('aria-pressed', String(selection.has(value))); renderTags();
      }, 'secondary');
      control.setAttribute('aria-pressed', 'false'); toggles.push({ control, selection, value }); group.append(control);
    }
    filters.append(group);
  };
  filterGroup('State', selected.state, keys.map(key => key.stateText), value => value);
  filterGroup('Platform', selected.host, keys.flatMap(key => key.places.map(place => place.host)), hostName);
  filterGroup('Provider', selected.provider, keys.map(key => key.provider), providerName);
  filters.append(button('Clear filters', () => {
    for (const filter of toggles) { filter.selection.clear(); filter.control.setAttribute('aria-pressed', 'false'); }
    renderTags();
  }, 'secondary'));
  page.addEventListener('keydown', event => { if (event.key === 'Escape' && selectedTag) { event.preventDefault(); close(); } });
  cabinet.append(grid, detail); page.append(filters, results, cabinet); renderTags(); return page;
}
