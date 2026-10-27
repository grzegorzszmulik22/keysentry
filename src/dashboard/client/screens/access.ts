import { get } from '../api.js';
import { emptyState, notice } from '../components.js';

interface AccessItem {
  area: string;
  status: 'ok' | 'warn' | 'fail' | 'info';
  title: string;
  detail: string;
  fix?: string;
}

interface AccessResponse { items: AccessItem[] }

/** Doctor reports describe permissions and checks; no token values are requested. */
export async function renderAccess(): Promise<HTMLElement> {
  const { items } = await get<AccessResponse>('access');
  const page = document.createElement('div'); page.className = 'screen-a-access';
  const introduction = document.createElement('p');
  introduction.textContent = 'Review what your tokens allow, how keysentry uses them, and any changes the checks recommend.';
  page.append(introduction);
  if (items.length === 0) {
    page.append(emptyState('No access checks are available yet. Connect a platform to review its token permissions.'));
    const link = document.createElement('a'); link.href = '#/connect'; link.textContent = 'Connect a platform'; page.append(link);
    return page;
  }

  const groups = new Map<string, AccessItem[]>();
  for (const item of items) {
    const group = groups.get(item.area) ?? []; group.push(item); groups.set(item.area, group);
  }
  const kinds = { ok: 'ok', warn: 'attention', fail: 'stop', info: 'info' } as const;
  for (const [area, checks] of groups) {
    const section = document.createElement('section'); section.className = 'screen-a-section';
    const heading = document.createElement('h2'); heading.textContent = area; section.append(heading);
    for (const item of checks) {
      const check = notice(kinds[item.status], item.title, item.detail);
      const title = check.querySelector('h2');
      const nestedTitle = document.createElement('h3'); nestedTitle.textContent = item.title; title?.replaceWith(nestedTitle);
      if (item.fix) {
        const fix = document.createElement('p'); fix.className = 'screen-a-fix'; fix.textContent = `Next step: ${item.fix}`; check.append(fix);
      }
      section.append(check);
    }
    page.append(section);
  }
  return page;
}
