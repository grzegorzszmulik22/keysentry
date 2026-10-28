import { createHash } from 'node:crypto';
import type { CredentialSource, HttpClient, Vault } from '../types.js';
import type { checkLocalIntegrity } from '../release/index.js';
import { credentialVaultName } from '../vault/credentials.js';
import { detectAgentEnvironment, MEMORY_ONLY_ROTATION_WARNING, sandboxSupport } from '../safety/index.js';
import { TOKEN_CAPABILITIES, type PlatformCapabilities } from './capabilities.js';

export interface DoctorItem {
  area: string;
  status: 'ok' | 'warn' | 'fail' | 'info';
  title: string;
  detail: string;
  fix?: string;
}

export interface DoctorInput {
  vault: Vault;
  credentials: CredentialSource;
  enabledHosts: string[];
  env: NodeJS.ProcessEnv;
  nodeVersion: string;
  probe?: { http: HttpClient };
  previous?: Record<string, string>;
  integrity: Awaited<ReturnType<typeof checkLocalIntegrity>>;
  sandboxed: boolean;
}

export interface DoctorResult {
  items: DoctorItem[];
  fingerprints: Record<string, string>;
}

// These names match the hosting adapter configuration and vault credential API.
const HOST_CREDENTIALS: Record<string, readonly string[]> = {
  railway: ['RAILWAY_TOKEN', 'RAILWAY_PROJECT_TOKEN'],
  vercel: ['VERCEL_TOKEN'], render: ['RENDER_API_KEY'], fly: ['FLY_API_TOKEN'],
  'github-actions': ['GITHUB_TOKEN'],
};

// The public input has no configured-provider list. A provider is configured when
// at least one of its credentials is present. AWS needs both members of its pair.
const PROVIDER_CREDENTIALS: Record<string, readonly string[]> = {
  openai: ['OPENAI_ADMIN_KEY'], anthropic: ['ANTHROPIC_ADMIN_KEY'],
  openrouter: ['OPENROUTER_PROVISIONING_KEY'], resend: ['RESEND_ADMIN_KEY'],
  cloudflare: ['CLOUDFLARE_ADMIN_TOKEN'], aws: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'],
};

type Credential = Awaited<ReturnType<CredentialSource['get']>>;
interface TokenState {
  read: Credential;
  write: Credential;
  separateRead: boolean;
}

const NODE_DOWNLOAD = 'https://nodejs.org/en/download';
const PACKAGE_URL = 'https://www.npmjs.com/package/keysentry';

function installItem(integrity: DoctorInput['integrity']): DoctorItem {
  switch (integrity.status) {
    case 'ok': return { area: 'install', status: 'ok', title: 'Installation integrity', detail: 'The bundle matches the local release manifest; publisher authenticity is checked separately by keysentry verify.' };
    case 'mismatch': return { area: 'install', status: 'fail', title: 'Installation integrity', detail: 'The bundle does not match its local release manifest; reinstall from the official package.', fix: PACKAGE_URL };
    case 'dev': return { area: 'install', status: 'info', title: 'Development installation', detail: 'Running from development sources; no release bundle integrity was checked.' };
    case 'missing-manifest': return { area: 'install', status: 'warn', title: 'Release manifest missing', detail: 'The local release manifest is missing, so bundle integrity could not be checked.', fix: PACKAGE_URL };
  }
}

function nodeItem(input: DoctorInput): DoctorItem {
  const support = sandboxSupport(input.nodeVersion);
  const minimum = support.minimum
    ? `Minimum sandbox version for this line: ${support.minimum}.`
    : 'Supported sandbox minimum versions: 22.23.4, 24.22.1 and 26.12.1.';
  if (input.sandboxed) return {
    area: 'node', status: support.supported ? 'ok' : 'warn', title: `Node ${input.nodeVersion}`,
    detail: `Node permission sandbox is on.${support.reason ? ` ${support.reason}.` : ''} ${minimum} The egress guard controls network access. Inside the sandbox Node cannot force saved data to disk, so a power loss during a rotation can lose its newest value; keysentry then reports a possible leftover key instead of revoking anything.`,
    ...(!support.supported ? { fix: NODE_DOWNLOAD } : {}),
  };
  const reason = input.env.KEYSENTRY_NO_SANDBOX === '1'
    ? 'opted out with KEYSENTRY_NO_SANDBOX=1'
    : support.reason ?? (process.argv[1]?.endsWith('.mjs')
      ? 'permissions are not enabled in this process'
      : 'running from TypeScript sources');
  return {
    area: 'node', status: 'warn', title: `Node ${input.nodeVersion}`,
    detail: `Node permission sandbox is off: ${reason}. ${minimum} The egress guard controls network access.`,
    fix: input.env.KEYSENTRY_NO_SANDBOX === '1' || support.supported ? 'keysentry doctor' : NODE_DOWNLOAD,
  };
}

function guidance(capability: PlatformCapabilities): { detail: string; fix: string } {
  const token = capability.tokens.find(token => token.recommended && !token.canWrite)
    ?? capability.tokens.find(token => token.recommended)!;
  return {
    detail: `For scanning, use the narrowest available token: ${token.name}. ${token.scope} ${token.howToCreate} Scan: ${capability.keysentryUses.scan} Rotate: ${capability.keysentryUses.rotate}`,
    fix: token.howToCreate.match(/https:\/\/[^\s]+/)![0].replace(/[.,]$/, ''),
  };
}

/** Local diagnostics are read-only. Only an explicit probe makes HTTP requests. */
export async function runDoctor(input: DoctorInput): Promise<DoctorResult> {
  const memoryOnly = input.vault.backend === 'env' || input.vault.backend === 'memory';
  const vaultWarning = [input.vault.weakness, memoryOnly ? MEMORY_ONLY_ROTATION_WARNING : undefined].filter(Boolean).join(' ');
  const items: DoctorItem[] = [installItem(input.integrity), nodeItem(input), {
    area: 'vault', status: vaultWarning ? 'warn' : 'ok', title: 'Credential vault',
    detail: `Backend: ${input.vault.backend}.${vaultWarning ? ` ${vaultWarning}` : ''}`,
    ...(vaultWarning ? { fix: 'keysentry vault status' } : {}),
  }];
  const fingerprints: Record<string, string> = {};
  const secrets = new Set<string>();
  const cache = new Map<string, TokenState>();

  async function tokenState(name: string): Promise<TokenState> {
    const cached = cache.get(name);
    if (cached) return cached;
    const write = await input.credentials.get(name, 'write');
    const read = await input.credentials.get(name, 'read');
    if (write?.value) secrets.add(write.value);
    if (read?.value) secrets.add(read.value);
    const explicitRead = await input.vault.get(credentialVaultName(name, 'read'));
    let separateRead = false;
    if (explicitRead !== null) {
      try {
        const value = explicitRead.toString('utf8');
        if (value) secrets.add(value);
        separateRead = !!value && input.vault.backend !== 'env'
          && read?.source === 'vault' && value === read.value && value !== write?.value;
      } finally { explicitRead.fill(0); }
    }
    const result = { read, write, separateRead };
    cache.set(name, result);
    return result;
  }

  function reportTokens(platform: string, tokens: { name: string; state: TokenState }[]): void {
    const capability = TOKEN_CAPABILITIES[platform]!;
    const present = tokens.filter(({ state }) => state.write || state.read);
    if (present.length === 0) {
      const name = tokens[0]!.name;
      items.push({
        area: 'tokens', status: 'warn', title: `${capability.platform}: ${tokens.map(token => token.name).join(' or ')}`,
        detail: 'No token is configured in the vault or environment.', fix: `keysentry vault set ${name}`,
      });
      return;
    }
    for (const { name, state } of tokens) {
      const credential = state.write ?? state.read;
      if (!credential) {
        // Host names are alternatives. AWS credentials are a required pair.
        if (platform === 'aws') items.push({ area: 'tokens', status: 'warn', title: `${capability.platform}: ${name}`, detail: 'This credential is missing from the configured AWS access-key pair.', fix: `keysentry vault set ${name}` });
        continue;
      }
      const environment = state.write?.source === 'env' || state.read?.source === 'env';
      items.push({
        area: 'tokens', status: environment ? 'warn' : 'ok', title: `${capability.platform}: ${name}`,
        detail: `${name} is ${environment ? 'stored in an environment variable' : 'present in the vault'}. Scan: ${capability.keysentryUses.scan} Rotate: ${capability.keysentryUses.rotate}`,
        ...(environment ? { fix: 'keysentry vault import-env' } : {}),
      });
      if (state.separateRead) {
        items.push({ area: 'tokens', status: 'ok', title: `${name}: read role`, detail: 'A separate read-role token is configured in the vault; its actual permissions are not inferred from the role name.' });
      } else {
        items.push({ area: 'tokens', status: 'info', title: `${name}: read role`, ...guidance(capability) });
      }
    }
  }

  for (const host of new Set(input.enabledHosts)) {
    if (!Object.hasOwn(HOST_CREDENTIALS, host)) continue;
    const tokens = [];
    for (const name of HOST_CREDENTIALS[host]!) tokens.push({ name, state: await tokenState(name) });
    reportTokens(host, tokens);
  }
  for (const [provider, names] of Object.entries(PROVIDER_CREDENTIALS)) {
    const tokens = [];
    for (const name of names) tokens.push({ name, state: await tokenState(name) });
    if (tokens.some(({ state }) => state.write || state.read)) reportTokens(provider, tokens);
  }

  const agent = detectAgentEnvironment(input.env);
  if (agent) items.push({
    area: 'agent', status: 'info', title: `Coding agent: ${agent.agent}`,
    detail: `Detected ${agent.marker}; keysentry will refuse changes in this terminal.`,
  });

  if (input.probe) {
    const github = await tokenState('GITHUB_TOKEN');
    const credential = github.write ?? github.read;
    if (!credential) {
      items.push({ area: 'probe', status: 'info', title: 'GitHub probe skipped', detail: 'No GITHUB_TOKEN is available for the GitHub probe.', fix: 'keysentry vault set GITHUB_TOKEN' });
    } else {
      try {
        const response = await input.probe.http.request({
          method: 'GET', url: 'https://api.github.com/user',
          headers: { Authorization: `Bearer ${credential.value}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
        });
        if (response.status < 200 || response.status >= 300) {
          items.push({ area: 'probe', status: 'warn', title: 'GitHub probe', detail: `GitHub could not confirm GITHUB_TOKEN (HTTP ${response.status}).`, fix: 'https://github.com/settings/tokens' });
        } else {
          const body = response.json<unknown>();
          if (!body || typeof body !== 'object' || !('login' in body) || typeof body.login !== 'string' || !body.login.trim()) throw new Error('Invalid GitHub identity response.');
          // Header names are case-insensitive. Only scopes, not account identity or
          // token values, contribute to the persisted permission fingerprint.
          const scopesHeader = Object.entries(response.headers).find(([name]) => name.toLowerCase() === 'x-oauth-scopes')?.[1];
          const scopes = scopesHeader?.split(',').map(scope => scope.trim()).filter(Boolean).sort() ?? [];
          fingerprints.github = createHash('sha256').update(scopes.join(',')).digest('hex');
          items.push({
            area: 'probe', status: 'ok', title: 'GitHub: GITHUB_TOKEN',
            detail: `Login: ${body.login}. ${scopesHeader === undefined ? 'fine-grained token (no scopes header)' : `OAuth scopes: ${scopes.join(', ') || '(none)'}`}.`,
          });
          if (input.previous?.github !== undefined && input.previous.github !== fingerprints.github) items.push({
            area: 'probe', status: 'warn', title: 'GitHub token permissions',
            detail: "This token's permissions changed since the last doctor run.", fix: 'https://github.com/settings/tokens',
          });
        }
      } catch {
        // Transport errors and response bodies may contain credentials. Neither is
        // included in diagnostics, even when the injected client reports them.
        items.push({ area: 'probe', status: 'warn', title: 'GitHub probe', detail: 'GitHub permissions could not be checked; the request failed or returned an unreadable response.', fix: 'keysentry doctor --probe' });
      }
    }
  }

  // Treat identity and header fields as untrusted output. In particular a server
  // must not be able to echo any loaded credential into printable diagnostics.
  const redact = (value: string): string => {
    for (const secret of [...secrets].sort((left, right) => right.length - left.length)) value = value.split(secret).join('«redacted»');
    return value;
  };
  for (const item of items) {
    item.title = redact(item.title);
    item.detail = redact(item.detail);
    if (item.fix) item.fix = redact(item.fix);
  }
  return { items, fingerprints };
}
