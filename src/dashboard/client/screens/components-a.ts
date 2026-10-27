import { table } from '../components.js';

/** Browser-local projections of docs/design/dashboard-api.md; no server runtime is imported. */
export interface KeyView {
  id: string; provider: string; tier: string; hint: string | null;
  method: 'auto' | 'atomic-roll' | 'generate' | 'guided';
  places: { label: string; host: string; variable: string; writeOnly: boolean }[];
  inGitHistory: boolean; ageDays?: number; rotateBy?: string; armed: boolean;
  state: 'ok' | 'attention' | 'stop'; stateText: string;
}

export interface OverviewResponse {
  firstRun: {
    scannedFiles: number; scannedCommits: number; historyComplete: boolean; elapsedMs: number;
    deployTargets: { host: string; evidence: string }[]; nextSteps: string[];
  } | null;
  connectedPlatforms: string[]; keys: number; inGitHistory: number; needsRotation: number;
  autopilot: 'off' | 'armed' | 'alert-only' | 'disarmed'; nextSteps: string[];
}

export interface PlatformView {
  host: string; name: string; connected: boolean; source?: 'vault' | 'env'; roles: ('read' | 'write')[];
  tokens: {
    name: string; canReadValues: boolean; canWrite: boolean; scope: string;
    recommended: boolean; howToCreate: string; source: string;
  }[];
  keysentryUses: { scan: string; rotate: string };
}

export function element<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, className?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

export function section(title: string): HTMLElement {
  const block = element('section', undefined, 'screen-a-section'); block.append(element('h2', title)); return block;
}

export function routeLink(text: string, route: string): HTMLAnchorElement {
  const anchor = element('a', text); anchor.href = `#/${route}`; return anchor;
}

export function count(value: number, singular: string, plural = `${singular}s`): string {
  return `${value} ${value === 1 ? singular : plural}`;
}

const hosts: Record<string, string> = {
  railway: 'Railway', vercel: 'Vercel', render: 'Render', fly: 'Fly', 'github-actions': 'GitHub Actions', dotenv: 'Local files',
};
export function hostName(host: string): string { return hosts[host] ?? host; }

const providers: Record<string, string> = {
  openai: 'OpenAI', anthropic: 'Anthropic', openrouter: 'OpenRouter', stripe: 'Stripe', resend: 'Resend',
  cloudflare: 'Cloudflare', github: 'GitHub', aws: 'AWS', supabase: 'Supabase', database: 'Database', slack: 'Slack',
  sendgrid: 'SendGrid', twilio: 'Twilio', google: 'Google', 'private-key': 'Private key', 'crypto-wallet': 'Wallet',
  'app-secret': 'App secret', 'encryption-key': 'Encryption key', unknown: 'Unknown provider',
};
export function providerName(provider: string): string { return providers[provider] ?? provider; }

export function scrollTable(columns: string[], rows: (string | Node)[][], caption: string): HTMLElement {
  const wrapper = element('div', undefined, 'table-scroll');
  wrapper.tabIndex = 0; wrapper.setAttribute('role', 'region'); wrapper.setAttribute('aria-label', caption);
  wrapper.append(table(columns, rows, caption)); return wrapper;
}

/** Documentation is an outbound link only; never turn an arbitrary response into executable navigation. */
export function documentationLink(url: string): HTMLAnchorElement | null {
  try {
    const target = new URL(url);
    if (target.protocol !== 'https:' || target.username || target.password) return null;
    const anchor = element('a', 'How to create it'); anchor.href = target.href;
    anchor.target = '_blank'; anchor.rel = 'noopener noreferrer'; return anchor;
  } catch { return null; }
}
