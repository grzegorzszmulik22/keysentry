import { get } from '../api.js';
import { emptyState, table } from '../components.js';

interface AllowedHost {
  host: string;
  purpose: string;
  source: 'built in' | 'added by you in keysentry.yaml' | 'added by an environment variable';
}

interface ReceiptRow { host: string; purpose: string; count: number; blocked: number; lastAt: string }
/** `status`: the proxy, extra CA and offline lines `keysentry network` prints; `feeds`: whether breach feeds are polled. */
interface NetworkResponse { allowed: AllowedHost[]; receipt: ReceiptRow[]; status?: string[]; feeds?: 'offline' | 'polled' }

function scrollTable(content: HTMLTableElement): HTMLElement {
  const wrapper = document.createElement('div'); wrapper.className = 'table-scroll';
  wrapper.tabIndex = 0; wrapper.setAttribute('role', 'region'); wrapper.setAttribute('aria-label', content.caption?.textContent ?? 'Network details');
  wrapper.append(content); return wrapper;
}

/** Hosts and aggregate request metadata only; paths and request bodies are never rendered. */
export async function renderNetwork(): Promise<HTMLElement> {
  const { allowed, receipt, status, feeds } = await get<NetworkResponse>('network');
  const page = document.createElement('div'); page.className = 'screen-a-network';
  const introduction = document.createElement('p');
  introduction.textContent = 'These are the hosts keysentry is allowed to contact and the requests recorded in your network receipt.';
  page.append(introduction);
  // Proxy, extra certificates and offline mode, as `keysentry network` reports them (plain text, no values).
  for (const line of Array.isArray(status) ? status : []) {
    if (typeof line !== 'string') continue;
    const item = document.createElement('p'); item.textContent = line; page.append(item);
  }
  if (feeds === 'offline' && !(Array.isArray(status) && status.some(line => typeof line === 'string' && line.startsWith('Offline mode')))) {
    const offline = document.createElement('p'); offline.textContent = 'Offline mode: keysentry fetches no breach feeds or news.'; page.append(offline);
  }

  if (allowed.length === 0) page.append(emptyState('No hosts are allowed in this configuration. Review keysentry.yaml to configure network access.'));
  const groups = new Map<string, AllowedHost[]>();
  for (const host of allowed) {
    const group = groups.get(host.purpose) ?? []; group.push(host); groups.set(host.purpose, group);
  }
  for (const [purpose, hosts] of groups) {
    const section = document.createElement('section'); section.className = 'screen-a-section';
    const heading = document.createElement('h2'); heading.textContent = purpose;
    section.append(heading, scrollTable(table(['Host', 'Source'], hosts.map(host => [host.host, host.source]), `Allowed hosts: ${purpose}`)));
    page.append(section);
  }

  const history = document.createElement('section'); history.className = 'screen-a-section';
  const historyHeading = document.createElement('h2'); historyHeading.textContent = 'Receipt'; history.append(historyHeading);
  if (receipt.length === 0) history.append(emptyState('No requests have been recorded yet. Requests will appear here when keysentry contacts a platform.'));
  else history.append(scrollTable(table(
    ['Host', 'Purpose', 'Requests', 'Blocked', 'Last contacted'],
    receipt.map(row => [row.host, row.purpose, String(row.count), String(row.blocked), row.lastAt]),
    'Network receipt',
  )));
  page.append(history);
  return page;
}
