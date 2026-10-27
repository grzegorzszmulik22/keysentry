import { get, post } from '../api.js';
import type { DashboardSession } from '../api.js';
import { emptyState, notice, table } from '../components.js';
import { actions, dateTime, download, el, field, input, lifetime, paragraph, scrollTable, section, status, taskButton } from './components-b.js';

interface Activity { verify: { ok: boolean; problem?: string }; entries: { at: string; kind: string; summary: string }[] }
interface Timeline { events: { at: string; kind: string; summary: string }[]; markdown: string }

export async function renderActivity(_session: DashboardSession): Promise<HTMLElement> {
  const data = await get<Activity>('activity'); const root = el('div', undefined, 'screen-b'); const scope = lifetime(root); const feedback = status();
  const audit = notice(data.verify.ok ? 'ok' : 'attention', data.verify.ok ? 'Audit check passed' : 'Audit needs review', data.verify.ok ? 'The recorded audit entries passed verification.' : data.verify.problem ?? 'The audit could not be verified. Review the local audit log.');
  const timeline = el('div'); const id = input('id', 'text', new URLSearchParams(location.hash.split('?')[1]).get('id') ?? ''); id.required = true;
  const load = taskButton('Timeline', feedback, async () => {
    const selected = id.value.trim(); if (!selected) { feedback.textContent = 'Enter a plan or wave ID.'; return; }
    const result = await post<Timeline>('timeline', { id: selected }); if (scope.signal.aborted) return;
    const exportButton = taskButton('Download Markdown', feedback, async () => { download(new Blob([result.markdown], { type: 'text/markdown;charset=utf-8' }), 'keysentry-timeline.md'); });
    timeline.replaceChildren(section('Timeline', result.events.length ? scrollTable(table(['When', 'Event', 'Details'], result.events.map(event => [dateTime(event.at), event.kind, event.summary]), 'Incident timeline')) : emptyState('No events recorded for this plan or wave.'), actions(exportButton)));
  });
  const form = el('form', undefined, 'b-form'); form.append(field('Plan or wave ID', id), actions(load)); form.addEventListener('submit', event => { event.preventDefault(); load.click(); });
  root.append(audit, section('Audit entries', data.entries.length ? scrollTable(table(['When', 'Event', 'Details'], data.entries.map(entry => [dateTime(entry.at), entry.kind, entry.summary]), 'Recent audit entries')) : emptyState('No audit entries yet.')),
    section('View a timeline', paragraph('Choose a plan or wave to review its events and download a Markdown copy.'), form), feedback, timeline);
  scope.onMount(() => { if (id.value) load.click(); });
  return root;
}
