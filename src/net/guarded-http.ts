import type { EgressRule, HttpClient, HttpRequest, HttpResponse, Logger, NetworkReceipt, NetworkReceiptEntry } from '../types.js';
import { createRedactor } from '../core/redact.js';
import { matchRule } from './allowlist.js';

export class EgressBlockedError extends Error {
  readonly code = 'EGRESS_BLOCKED';

  constructor(host: string) {
    super(`Blocked a request to ${createRedactor().redact(host)}: it is not on keysentry's list of allowed hosts. Run "keysentry network" to see the list.`);
    this.name = 'EgressBlockedError';
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
// API owners stay on one host, including within a provider's wildcard rule.
const CROSS_HOST_REDIRECT_OWNERS = new Set(['feed', 'release', 'notify', 'user']);
const hostOf = (url: URL): string => url.hostname.toLowerCase().replace(/\.$/, '');
/** Scheme, normalized host and effective port: another port of the same host is another server. */
const originOf = (url: URL): string => `${url.protocol}//${hostOf(url)}:${url.port || (url.protocol === 'http:' ? '80' : '443')}`;

function isCredentialHeader(name: string): boolean {
  return /token|secret|key|auth/i.test(name)
    || ['cookie', 'openai-organization'].includes(name.toLowerCase());
}

export function createGuardedHttp(inner: HttpClient, opts: {
  rules: readonly EgressRule[];
  receipt?: NetworkReceipt;
  log?: Logger;
  maxRedirects?: number;
  now?: () => Date;
  /**
   * Exact URLs the user configured whose path carries a credential by design (Slack/Discord webhooks, Telegram bot
   * URLs). Only a request to exactly one of these skips the secret-in-URL check; it must still match a rule, and
   * redirect targets never inherit the exemption.
   */
  trustedUrls?: readonly string[];
}): HttpClient {
  const redactor = createRedactor();
  const now = opts.now ?? (() => new Date());
  const maxRedirects = opts.maxRedirects ?? 3;
  const trusted = new Set<string>();
  for (const value of opts.trustedUrls ?? []) {
    try { trusted.add(new URL(value).href); } catch { /* rulesForUserUrls already rejected unparseable URLs */ }
  }

  function containsSecret(text: string): boolean {
    if (redactor.redact(text) !== text) return true;
    // Percent-encoding a key must not bypass the same check on literal keys.
    try {
      const decoded = decodeURIComponent(text);
      return redactor.redact(decoded) !== decoded;
    } catch {
      return false;
    }
  }

  async function record(entry: Omit<NetworkReceiptEntry, 'at'>): Promise<void> {
    if (!opts.receipt) return;
    try {
      await opts.receipt.record({ at: now().toISOString(), ...entry });
    } catch {
      // Filesystem errors can include paths. Do not copy the exception into logs.
      try { opts.log?.warn('Could not write the network receipt.', { host: entry.host }); } catch { /* Logging must not change a request's result either. */ }
    }
  }

  async function blocked(host: string, method: string): Promise<never> {
    const safeHost = redactor.redact(host);
    await record({ host: safeHost, method, purpose: 'not on the allowed list', allowed: false });
    throw new EgressBlockedError(safeHost);
  }

  return {
    async request(req: HttpRequest): Promise<HttpResponse> {
      let current: HttpRequest = { ...req, headers: req.headers ? { ...req.headers } : undefined };
      let owner: string | undefined;
      let firstHost: string | undefined;
      let redirects = 0;
      let bodyToOtherOrigin = false;

      for (;;) {
        let url: URL;
        try { url = new URL(current.url); } catch { return blocked('(unparseable)', current.method); }
        const host = hostOf(url);
        const rule = matchRule(url, opts.rules);
        const exempt = redirects === 0 && trusted.has(url.href);
        if (!rule || (!exempt && (containsSecret(current.url) || containsSecret(url.href)))
          || (owner !== undefined && rule.owner !== owner)
          || (firstHost !== undefined && host !== firstHost && !CROSS_HOST_REDIRECT_OWNERS.has(rule.owner))) {
          return blocked(host, current.method);
        }
        // A 307/308 resends the body, and bodies carry secret values (a Vault PATCH, a whole Kubernetes Secret, a
        // client secret): they never follow a redirect to another origin, even one the rules allow.
        if (bodyToOtherOrigin) {
          const safeHost = redactor.redact(host);
          await record({ host: safeHost, method: current.method, purpose: 'redirect that would resend a request body to another server', allowed: false });
          throw new EgressBlockedError(safeHost);
        }
        // Classify forbidden targets before the hop limit so their blocked attempt is still recorded.
        if (redirects > 0 && redirects > maxRedirects) throw new Error(`Too many redirects from ${firstHost}`);
        owner ??= rule.owner;
        firstHost ??= host;

        let response: HttpResponse;
        try {
          response = await inner.request(current);
        } catch (error) {
          await record({ host, method: current.method, purpose: rule.purpose, allowed: true });
          throw error;
        }
        await record({ host, method: current.method, purpose: rule.purpose, allowed: true, status: response.status });

        const location = Object.entries(response.headers).find(([name]) => name.toLowerCase() === 'location')?.[1];
        if (!REDIRECT_STATUSES.has(response.status) || location === undefined) return response;
        const next: HttpRequest = { ...current, headers: current.headers ? { ...current.headers } : undefined };
        if (response.status === 303 || ((response.status === 301 || response.status === 302) && !['GET', 'HEAD'].includes(current.method))) {
          next.method = 'GET';
          delete next.body;
          for (const name of Object.keys(next.headers ?? {})) {
            if (['content-length', 'content-type'].includes(name.toLowerCase())) delete next.headers![name];
          }
        }

        let target: URL;
        try { target = new URL(location, url); } catch { return blocked('(unparseable)', next.method); }
        if (originOf(target) !== originOf(url)) {
          bodyToOtherOrigin = next.body !== undefined && !['GET', 'HEAD'].includes(next.method);
          for (const name of Object.keys(next.headers ?? {})) {
            if (isCredentialHeader(name)) delete next.headers![name];
          }
        }
        next.url = target.href;
        current = next;
        redirects += 1;
      }
    },
  };
}
