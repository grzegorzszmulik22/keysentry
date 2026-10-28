import { createFetchHttp } from '../http.js';
import { resolveFeedMode, type FeedMode } from '../feeds/index.js';
import {
  CaBundleError, TransportConfigError, createNodeTransport, createProxyHealth, createUnavailableTransport, loadCaBundle, parseCaBundle, resolveProxySettings,
  summarizeNetwork, type CaBundle, type NetworkSummary, type ResolvedProxy,
} from '../net/transport.js';
import type { HttpClient, Redactor, TeamPolicy, Vault } from '../types.js';
import type { ConfigSettings } from './config.js';

/**
 * The certificates from `network.caFile`, carried in a deployed watcher's encrypted vault by `watcher setup` (PEM text,
 * not a path: the path names a file on the computer that ran setup). When the vault holds it, it is used instead of
 * reading `network.caFile` from disk. A workstation's own vault never holds this entry.
 */
export const DEPLOYMENT_CA_VAULT_NAME = 'deployment/network/ca-bundle';

export interface RuntimeNetwork {
  feedMode: FeedMode;
  summary: NetworkSummary;
  /**
   * The raw transport every guarded client wraps: Node's fetch, or the proxy/CA transport (src/net/transport.ts) when
   * a proxy, an extra CA or a policy-required proxy is in play. A broken proxy, CA or policy setting gives a transport
   * that refuses every request, so keysentry never silently goes direct.
   */
  transport: HttpClient;
  /** The fixed-text reason requests are refused, or null. */
  problem: Error | null;
  /** The extra trusted certificates (PEM), for connections that do not use `transport` (syslog over TLS). */
  ca: string[] | null;
  /**
   * True after repeated failed connections to the configured proxy, until one opens again (review EA H1): a deployed
   * watcher then reports itself unhealthy on /healthz. Absent when no proxy carries requests.
   */
  proxyUnreachable?: () => boolean;
}

async function readCa(caFile: string, cwd: string, vault?: Pick<Vault, 'get'>): Promise<CaBundle> {
  const carried = await vault?.get(DEPLOYMENT_CA_VAULT_NAME);
  if (carried) {
    try { return parseCaBundle(carried, caFile); } finally { carried.fill(0); }
  }
  return loadCaBundle(caFile, { cwd });
}

/**
 * Phase 5 network settings (notes/network-enterprise.md). `policy` must be the verified SignedTeamPolicy.policy, or
 * null when team mode is off; an unverifiable policy must already have stopped the command.
 */
export async function setupNetwork(input: {
  settings: ConfigSettings['network'];
  cwd: string;
  env: NodeJS.ProcessEnv;
  vault?: Pick<Vault, 'get'>;
  redactor?: Pick<Redactor, 'register'>;
  policy: TeamPolicy | null;
  /** An injected client (tests, embedders) is used as given; the summary still describes the settings. */
  injected?: HttpClient;
}): Promise<RuntimeNetwork> {
  const { settings } = input;
  const feedMode = resolveFeedMode({ configOffline: settings.offline, policy: input.policy });
  const requireProxy = input.policy?.network.requireProxy === true;
  let problem: Error | null = null;
  let proxy: ResolvedProxy | null = null;
  try {
    // A team policy that requires the proxy makes it carry every request: no-proxy lists are ignored, not honoured.
    const env = requireProxy ? Object.fromEntries(Object.entries(input.env).filter(([name]) => name.toUpperCase() !== 'NO_PROXY')) : input.env;
    proxy = await resolveProxySettings({ configProxy: settings.proxy, configNoProxy: requireProxy ? [] : settings.noProxy, env,
      ...(input.vault ? { vault: input.vault } : {}), ...(input.redactor ? { redactor: input.redactor } : {}) });
  } catch (error) {
    if (!(error instanceof TransportConfigError)) throw error;
    problem = error;
  }
  let ca: CaBundle | { path: string; error: string } | null = null;
  if (settings.caFile) {
    try { ca = await readCa(settings.caFile, input.cwd, input.vault); }
    catch (error) {
      if (!(error instanceof CaBundleError)) throw error;
      ca = { path: settings.caFile, error: error.message };
      problem ??= error;
    }
  }
  const bundle = ca && 'pems' in ca ? ca : null;
  if (!problem && requireProxy && !proxy?.settings) {
    problem = new TransportConfigError('The team policy requires a proxy, but none is configured. Set network.proxy in keysentry.yaml or HTTPS_PROXY.');
  }
  const summary = summarizeNetwork({ proxy, requireProxy, ca, feeds: feedMode, env: input.env });
  // Fail closed: a broken proxy/CA/policy setting refuses every request instead of silently going direct. Node's fetch
  // honours NODE_TLS_REJECT_UNAUTHORIZED=0; keysentry's own transport pins certificate checks, so it is used then.
  const proxyHealth = !input.injected && !problem && proxy?.settings ? createProxyHealth() : null;
  const transport = input.injected ?? (problem ? createUnavailableTransport(problem)
    : proxy?.settings || bundle || requireProxy || summary.nodeTrust?.tlsChecksOff
      ? createNodeTransport({ ...(proxy?.settings ? { proxy: proxy.settings } : {}), ...(proxy ? { noProxy: proxy.noProxy } : {}),
        ...(bundle ? { ca: bundle.pems } : {}), requireProxy, ...(proxyHealth ? { onProxyResult: proxyHealth.record } : {}) })
      : createFetchHttp());
  return { feedMode, summary, transport, problem, ca: bundle ? [...bundle.pems] : null,
    ...(proxyHealth ? { proxyUnreachable: proxyHealth.unreachable } : {}) };
}
