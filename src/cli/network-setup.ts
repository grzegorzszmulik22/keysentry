import { createFetchHttp } from '../http.js';
import { resolveFeedMode, type FeedMode } from '../feeds/index.js';
import {
  CaBundleError, TransportConfigError, createNodeTransport, createUnavailableTransport, loadCaBundle, resolveProxySettings,
  summarizeNetwork, type CaBundle, type NetworkSummary, type ResolvedProxy,
} from '../net/transport.js';
import type { HttpClient, Redactor, TeamPolicy, Vault } from '../types.js';
import type { ConfigSettings } from './config.js';

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
    proxy = await resolveProxySettings({ configProxy: settings.proxy, configNoProxy: settings.noProxy, env: input.env,
      ...(input.vault ? { vault: input.vault } : {}), ...(input.redactor ? { redactor: input.redactor } : {}) });
  } catch (error) {
    if (!(error instanceof TransportConfigError)) throw error;
    problem = error;
  }
  let ca: CaBundle | { path: string; error: string } | null = null;
  if (settings.caFile) {
    try { ca = await loadCaBundle(settings.caFile, { cwd: input.cwd }); }
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
  const summary = summarizeNetwork({ proxy, requireProxy, ca, feeds: feedMode });
  // Fail closed: a broken proxy/CA/policy setting refuses every request instead of silently going direct.
  const transport = input.injected ?? (problem ? createUnavailableTransport(problem)
    : proxy?.settings || bundle || requireProxy
      ? createNodeTransport({ ...(proxy?.settings ? { proxy: proxy.settings } : {}), ...(proxy ? { noProxy: proxy.noProxy } : {}),
        ...(bundle ? { ca: bundle.pems } : {}), requireProxy })
      : createFetchHttp());
  return { feedMode, summary, transport, problem };
}
