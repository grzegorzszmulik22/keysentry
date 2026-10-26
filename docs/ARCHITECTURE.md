# keysentry architecture and module specs

keysentry is a local-first CLI (plus an MCP server for coding agents). It finds every copy of every secret across a
team's hosts, rotates them in a safe order with one redeploy per service, verifies the new keys, revokes the old ones,
and monitors keys so it can contain or rotate them when it sees suspicious use.

The contracts every module implements are in `src/types.ts` (owned by the orchestrator; do not edit). All network
access goes through `HttpClient` (`src/http.ts`); tests use `FakeHttp` (`test/helpers/fake-http.ts`).

## Non-negotiable safety rules (every module)

1. **Never persist or print a plaintext secret.** On disk store only keyed fingerprints (`core/fingerprint`) and hints
   (prefix ≤ 7 chars + `…` + last 4, only for values ≥ 16 chars). Logs go through the `Redactor`. Error messages must
   not include request bodies or headers that contain secrets.
2. **Never delete or alter a variable keysentry was not asked to change.** Hosts whose API replaces the full set must
   read-modify-write. Railway: never `replace: true`.
3. **Dry-run is the default** for anything that writes to a host or a provider. Writes require `dryRun: false`.
4. **Revoke last.** An old key is revoked only after every consumer has the new value and (by default) the
   redeployments succeeded. Atomic-roll providers are the documented exception.
5. **No secrets in URLs or query strings.** Use headers/bodies.
6. **Fail closed.** If verification of a new key fails, stop that step, do not revoke the old key, report clearly.
7. Monitoring actions are rate-limited (cooldown per cluster, max automatic rotations per day) to prevent loops.

## Layout and ownership

| Path | Module | Wave |
|---|---|---|
| `src/types.ts`, `src/http.ts`, `test/helpers/*` | contracts and test helpers (orchestrator) | 0 |
| `src/core/` | fingerprint, classify, inventory, plan/runbook, redaction/logging, state store, random | 1 |
| `src/hosts/` | host adapters: railway, vercel, render, fly, github-actions, dotenv | 1 |
| `src/providers/` | provider adapters + registry | 1 |
| `src/rotate/` | rotation engine | 2 |
| `src/monitor/` | detectors, policy, canaries, daemon, notifier | 2 |
| `src/cli/`, `src/mcp/`, `skill/`, `README.md` | CLI, config, MCP server, agent skill, e2e tests | 3 |

Tests live in `test/<module>/*.test.ts`. Each module exports its public API from `src/<module>/index.ts`.

## Wave 1

### core (`src/core/`)
Public API (`src/core/index.ts`):
- `fingerprint.ts`
  - `loadOrCreateFingerprintKey(dir?: string): Promise<Buffer>`: 32 random bytes at `<dir ?? ~/.keysentry>/fingerprint.key`, created with mode 0o600 if missing; same key on every later call.
  - `fingerprint(value: string, key: Buffer): string`: HMAC-SHA256(key, value), hex, first 32 chars.
  - `makeHint(value: string): string | null`: `prefix + '…' + last4` where prefix is the known key prefix if one matches (e.g. `sk-or-v1-`, `sk_live_`, `sk-ant-`, `ghp_`, `AKIA`), else the first 4 chars; capped at 7 chars of prefix; null when `value.length < 16`.
- `classify.ts`
  - `classify(name: string, value: string | undefined): Classification`: provider + tier + isSecret + confidence from the variable name and value shape. Value patterns win over names. Must cover at least: OpenAI (`sk-proj-`, `sk-svcacct-`, `sk-` 40+), Anthropic (`sk-ant-api03-`, `sk-ant-admin01-`), OpenRouter (`sk-or-v1-`), Stripe (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`, `whsec_`; `pk_` is NOT secret), Resend (`re_`), Cloudflare (name contains CLOUDFLARE and TOKEN/KEY), GitHub (`ghp_`, `gho_`, `ghs_`, `ghu_`, `github_pat_`), AWS (`AKIA`/`ASIA` access key ids are **not** secrets themselves but mark the pair; `AWS_SECRET_ACCESS_KEY` 40-char is secret, provider aws), Supabase (`sb_secret_`, JWT whose payload role is `service_role`; anon key not secret), databases (`postgres://`, `postgresql://`, `mysql://`, `mongodb://`, `mongodb+srv://`, `redis://`, `rediss://` **with a password**), Slack (`xoxb-`, `xoxp-`, `hooks.slack.com/services/`), SendGrid (`SG.`), Twilio (name TWILIO and AUTH_TOKEN / API key `SK` + 32 hex), Google (`AIza`, service-account JSON with `"private_key"`), PEM private keys (`-----BEGIN ... PRIVATE KEY-----`), crypto wallets (0x + 64 hex in a name like PRIVATE_KEY/WALLET/MNEMONIC/SEED, 12/24-word mnemonics, base58 64–88 chars in such names), app secrets (names like `*_SECRET`, `JWT_SECRET`, `SESSION_SECRET`, `NEXTAUTH_SECRET`, `ENCRYPTION_KEY`, `COOKIE_SECRET` with random-looking values). Non-secrets: `NODE_ENV`, `PORT`, `HOST`, `NEXT_PUBLIC_*`, `VITE_*`, `PUBLIC_*`, booleans, numbers, plain URLs without credentials, Railway reference templates (`${{...}}`). Unknown random-looking values in names containing KEY/TOKEN/SECRET/PASSWORD → `unknown`, isSecret true, low confidence.
  - `methodFor(provider: ProviderId): RotationMethod`: default table: openai auto, openrouter auto, resend auto, aws auto, cloudflare atomic-roll, app-secret generate, everything else guided.
  - `tierFor(provider: ProviderId): RiskTier`: crypto-wallet→crypto; aws, cloudflare, github, google, private-key→cloud; database, supabase→database; stripe→payments; openai, anthropic, openrouter→ai; resend, sendgrid, slack, twilio→comms; app-secret→app; unknown→unknown.
- `service-key.ts`: `serviceKey(s: ServiceRef): string` = `${host}:${projectId}/${environmentId}/${serviceId}`.
- `inventory.ts`
  - `buildInventory(scans: HostScan[], key: Buffer, now?: Date): Inventory` where `HostScan = { host: HostId; services: { service: ServiceRef; vars: RawVariable[] }[]; error?: string }`. Classify every variable; keep only `isSecret` ones as findings; fingerprint readable values; cluster findings by fingerprint (same value under different names/services = one cluster); sealed findings become their own cluster `sealed:<serviceKey>:<varName>`. A cluster's provider/tier is the highest-confidence classification among its consumers. Cluster `method` = `methodFor(provider)`.
  - `scanHosts(hosts: HostAdapter[], key: Buffer, log: Logger): Promise<Inventory>`: listServices + readVariables per host with bounded concurrency (4); per-host errors go to `inventory.errors`, other hosts continue.
- `plan.ts`
  - `buildPlan(inv: Inventory, opts?: { tiers?: RiskTier[]; clusterIds?: string[]; hosts?: HostId[]; serviceKeys?: string[] }): RotationPlan`: filters clusters, orders by `TIER_ORDER`, then consumer count desc, then id; `services` = unique services of all consumers. Plan id: `plan-<yyyymmddHHMMss>-<4 hex>`.
  - `renderRunbook(plan: RotationPlan, inv: Inventory): string`: Markdown runbook: summary counts, then numbered steps (tier, provider, hint, method, every consumer as `host/service:VAR`), what to do per method (guided steps include the provider dashboard hint), and the "one redeploy per service" list. No values.
  - `renderBlastRadius(inv: Inventory): string`: Markdown report: totals, clusters with more than one consumer first ("this key lives in N places"), tier breakdown, sealed secrets that must be rotated blind, scan errors.
- `redact.ts`: `createRedactor(): Redactor` (registered values ≥ 6 chars are replaced by `«redacted»`; also masks any substring matching the high-confidence key patterns from classify); `createLogger(opts: { redactor: Redactor; level?: 'debug'|'info'|'warn'|'error'; json?: boolean; sink?: (line: string) => void }): Logger` writing redacted lines to stderr by default.
- `store.ts`: state lives in `<cwd>/.keysentry/`. `statePaths(cwd)`, `saveInventory`, `loadInventory`, `writeJsonAtomic(path, data)` (write temp + rename), `readJson`, `createFileJournal(path): Journal` (JSONL, append-only), `appendAudit(path, event)` (JSONL). Files are created with mode 0o600 where the OS supports it. A `.gitignore` containing `*` is written into `.keysentry/` on first use.
- `random.ts`: `generateSecret(likeValue?: string): string`: 32 random bytes; preserves the format of `likeValue` when it is clearly hex or base64/base64url of similar length; default base64url.

### hosts (`src/hosts/`)
One factory per host, all returning `HostAdapter`; `src/hosts/index.ts` re-exports them. Every factory takes `{ http: HttpClient; log: Logger; ... }`.

- **Railway** `createRailwayHost({ token, tokenType?: 'account' | 'project', projectIds?: string[], http, log })`. GraphQL `POST https://backboard.railway.com/graphql/v2`, header `Authorization: Bearer <token>` (account/workspace token) or `Project-Access-Token: <token>` (project token).
  - listServices: query projects → environments × services (one `ServiceRef` per environment × service). Also scan **shared** (environment-level) variables as a pseudo-service with `serviceId: ''`, `serviceName: 'shared'`.
  - readVariables: `variables(projectId, environmentId, serviceId, unrendered: true)` returns a JSON object name → value. Values that are Railway reference templates (`${{...}}`) are returned as-is (core classifies them as non-secrets). Names present with null/empty value for sealed variables → `sealed: true`.
  - writeVariables: `variableCollectionUpsert(input: { projectId, environmentId, serviceId, variables, replace: false, skipDeploys })`. Never `replace: true`.
  - redeploy: `serviceInstanceDeployV2(serviceId, environmentId)` (returns deployment id); for the shared pseudo-service return null. deploymentStatus: `deployment(id) { status }`: SUCCESS → success; FAILED/CRASHED/REMOVED → failed; else pending.
  - Handle GraphQL `errors` arrays as failures with the message (no secrets).
- **Vercel** `createVercelHost({ token, teamId?, targets?: ('production'|'preview'|'development')[], http, log })`. REST `https://api.vercel.com`, `Authorization: Bearer`, append `teamId` query param when set (it is not a secret).
  - listServices: `GET /v10/projects?limit=100` (follow `pagination.next` via `until`); one ServiceRef per project × target (default targets: production, preview); `environmentId = environmentName = target`.
  - readVariables: list `GET /v10/projects/{id}/env`; for each entry whose `target` includes the service's target: type `sensitive` (or `secret`) → sealed; otherwise fetch the decrypted value with `GET /v1/projects/{id}/env/{envId}` (returns `value`).
  - writeVariables: existing entry for that key and target → `PATCH /v9/projects/{id}/env/{envId}` `{ value }` (note: an entry may cover several targets; patching it updates them all, which is acceptable because the value is the same secret). Missing → `POST /v10/projects/{id}/env?upsert=true` `{ key, value, type: 'encrypted', target: [target] }`. Vercel writes never deploy.
  - redeploy: only for target `production`: latest READY production deployment `GET /v6/deployments?projectId={id}&target=production&state=READY&limit=1` → `POST /v13/deployments?forceNew=1` `{ name: projectName, deploymentId: <uid>, target: 'production' }` → new id. Other targets → null (applies on next deployment). deploymentStatus: `GET /v13/deployments/{id}` readyState READY → success; ERROR/CANCELED → failed; else pending.
- **Render** `createRenderHost({ apiKey, http, log })`. REST `https://api.render.com/v1`, `Authorization: Bearer`.
  - listServices: `GET /services?limit=100` (cursor pagination: items are `{ cursor, service }`). environmentId ''.
  - readVariables: `GET /services/{id}/env-vars?limit=100` (items `{ cursor, envVar: { key, value } }`).
  - writeVariables: per key `PUT /services/{id}/env-vars/{key}` `{ value }` (never the full-set PUT). Render API env-var updates do not deploy by themselves.
  - redeploy: `POST /services/{id}/deploys` `{ clearCache: 'do_not_clear' }` → `id`. deploymentStatus: `GET /services/{id}/deploys/{deployId}`: live → success; build_failed/update_failed/canceled/pre_deploy_failed/deactivated → failed; else pending.
  - (Optional, if time allows) environment groups `GET /env-groups` as pseudo-services named `envgroup:<name>`, write via `PUT /env-groups/{id}/env-vars/{key}`, redeploy null with a warning listing linked services.
- **Fly** `createFlyHost({ token, org?: string, apps?: string[], http, log })`. Values are write-only.
  - listServices: Machines API `GET https://api.machines.dev/v1/apps?org_slug=<org>` (or the configured app names).
  - readVariables: GraphQL `POST https://api.fly.io/graphql` `query($name:String!){ app(name:$name){ secrets { name digest createdAt } } }` → names only, `sealed: true`.
  - writeVariables: GraphQL `setSecrets(input: { appId, secrets: [{ key, value }], replaceAll: false })`. If the API cannot stage without deploying, document it in a code comment and still never deploy more than once per plan.
  - redeploy: return null and log a warning ("run `fly secrets deploy -a <app>`") unless a reliable API exists; deploymentStatus → success for null ids is never called.
- **GitHub Actions** `createGithubActionsHost({ token, repos: string[] /* owner/repo */, http, log })`. REST `https://api.github.com`, headers `Authorization: Bearer`, `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`.
  - One ServiceRef per repo (projectId = owner, serviceId = owner/repo). readVariables: `GET /repos/{o}/{r}/actions/secrets?per_page=100` → names, sealed.
  - writeVariables: `GET /repos/{o}/{r}/actions/secrets/public-key` → `{ key_id, key }`; encrypt with libsodium `crypto_box_seal` (package `libsodium-wrappers`, await `sodium.ready`); `PUT /repos/{o}/{r}/actions/secrets/{name}` `{ encrypted_value, key_id }`.
  - redeploy: null (secrets apply to the next workflow run).
- **dotenv** `createDotenvHost({ roots: string[], log, includeTemplates?: boolean })`. No network.
  - listServices: recursively find `.env` and `.env.*` files under each root (skip `node_modules`, `.git`, `dist`, `build`, `.keysentry`; skip `.env.example`, `.env.sample`, `.env.template`, `.env.dist` unless includeTemplates). ServiceRef: projectId = absolute root, serviceId = absolute file path, serviceName = path relative to root, environmentId ''.
  - readVariables: parse `KEY=VALUE`, `export KEY=VALUE`, single/double/back-quoted values (double-quoted may contain `\n` escapes and real newlines), inline `#` comments for unquoted values, blank lines and comments.
  - writeVariables: replace the values of existing keys in place, preserving everything else byte for byte (comments, ordering, quote style; quote the new value if it needs quoting); append missing keys at the end; atomic write (temp + rename); never create backup copies (they would duplicate secrets).
  - redeploy: null.

### providers (`src/providers/`)
One module per provider exporting a `ProviderAdapter`; `src/providers/index.ts` exports `getProvider(id: ProviderId): ProviderAdapter` (every ProviderId resolves; providers without automation get a guided adapter with good guidance) and `PROVIDER_CREDENTIALS: Record<ProviderId, string[]>` (the admin credential names each adapter reads from `ctx.credentials`). `verify` must treat 401 as `ok: false`; 403 on a read endpoint for restricted keys may mean valid-but-limited (say so in `identity`). Where no verify endpoint exists return `{ ok: true, identity: 'unverified' }`.

- **openai** (auto; credential `OPENAI_ADMIN_KEY`). verify `GET https://api.openai.com/v1/models` Bearer. resolveKeyRef: list projects `GET /v1/organization/projects?limit=100`, then `GET /v1/organization/projects/{pid}/api_keys?limit=100`; match `redacted_value` (e.g. `sk-proj-abc...wxyz`) by prefix and suffix; keyRef format `<projectId>/<keyId>` plus `/sa:<serviceAccountId>` when the owner is a service account. rotate: resolve the old key's project, `POST /v1/organization/projects/{pid}/service_accounts` `{ name: 'keysentry-<iso date>' }` → `api_key.value` is the new key; newKeyRef `<pid>/<api_key.id>/sa:<sa.id>`. revoke: service-account keys → `DELETE /v1/organization/projects/{pid}/service_accounts/{saId}`; user keys → `DELETE /v1/organization/projects/{pid}/api_keys/{keyId}`. listKeys: all project keys. usage: `GET /v1/organization/usage/completions?start_time=<unix>&end_time=<unix>&bucket_width=1h&api_key_ids=<keyId>&group_by=model` → sum `num_model_requests` and tokens; estimate costUsd from a small editable price table (document it as an estimate). cap: not supported (omit).
- **anthropic** (guided; credential `ANTHROPIC_ADMIN_KEY`). verify `GET https://api.anthropic.com/v1/models` with `x-api-key` and `anthropic-version: 2023-06-01`. listKeys `GET /v1/organizations/api_keys?limit=100&status=active` (`partial_key_hint`). resolveKeyRef by hint. revoke: `POST /v1/organizations/api_keys/{id}` `{ status: 'inactive' }`. cap = revoke (document that it breaks consumers). usage: `GET /v1/organizations/usage_report/messages?starting_at=<iso>&ending_at=<iso>&bucket_width=1h&api_key_ids[]=<id>&group_by[]=model`; estimate cost from tokens with an editable price table. guidance url `https://console.anthropic.com/settings/keys`.
- **openrouter** (auto; credential `OPENROUTER_PROVISIONING_KEY`). verify `GET https://openrouter.ai/api/v1/key` Bearer (`data.label`). listKeys `GET /api/v1/keys` (`data[]`: `hash`, `name`, `label`, `disabled`, `limit`, `usage`). resolveKeyRef: verify the value, take `data.label`, match a listed key's `label`. rotate: `POST /api/v1/keys` `{ name: 'keysentry-<date>', limit: <old limit if any> }` → `key` (new value), `data.hash`. revoke `DELETE /api/v1/keys/{hash}`. cap `PATCH /api/v1/keys/{hash}` `{ disabled: true }`. usage: from the list, `cumulativeCostUsd = usage`, `costUsd = 0` (the monitor diffs). Also export `createCanaryKey(ctx, name): Promise<{ value, keyRef }>` creating a key with `limit: 0.01` for decoys.
- **stripe** (guided). verify `GET https://api.stripe.com/v1/balance` Bearer; 401 invalid; 403 for restricted keys = valid-limited. `whsec_` webhook secrets: unverified, guidance to roll in the webhook endpoint settings. guidance url `https://dashboard.stripe.com/apikeys` (roll the key with an expiry on the old one).
- **resend** (auto; credential `RESEND_ADMIN_KEY`, a full-access key). verify `GET https://api.resend.com/domains` (403 for sending-only keys = valid-limited). rotate `POST https://api.resend.com/api-keys` `{ name, permission: 'full_access' }` → `token` and `id`. Old key ref is not identifiable (no hints): oldKeyRef null and a note telling the user which key to delete. revoke `DELETE /api-keys/{id}`.
- **cloudflare** (atomic-roll; credential `CLOUDFLARE_ADMIN_TOKEN` with API Tokens Write). verify `GET https://api.cloudflare.com/client/v4/user/tokens/verify` (`result.id`, `result.status`). rotate: id from verify of the old value, then `PUT /client/v4/user/tokens/{id}/value` with the admin token → `result` is the new value; oldRevoked: true; keyRef = token id.
- **github** (guided). verify `GET https://api.github.com/user` → `login`. guidance `https://github.com/settings/tokens`.
- **aws** (auto). verify: STS `GetCallerIdentity` with SigV4 (implement a small SigV4 signer in `providers/aws-sigv4.ts`, region us-east-1, service sts, POST form body). The access key id comes from `ctx.siblingVars.AWS_ACCESS_KEY_ID` (or a sibling ending in `_ACCESS_KEY_ID`). rotate: IAM `CreateAccessKey` (no UserName = calling user) signed with the old credentials → new id/secret; `companions` = `{ <access key id var name>: newId }`; oldKeyRef = old access key id; newKeyRef = new id. revoke(oldId): IAM `DeleteAccessKey` signed with the **new** credentials, which the engine passes via `ctx.siblingVars` at revoke time. Tests must check the SigV4 signature against an AWS documentation test vector.
- **supabase** (guided). verify only when `ctx.siblingVars` has `SUPABASE_URL`: `GET <url>/rest/v1/` with headers `apikey` and `Authorization: Bearer` → 2xx ok. guidance: project settings → API keys (new secret keys), service-role JWT rotation warning.
- **database** (guided). verify unverified. guidance: change the password at the database (Railway: Database tab → Regenerate; Neon/Supabase dashboards; `ALTER USER … PASSWORD`), then update the URL; never edit only the variable.
- **slack** (guided; verify `POST https://slack.com/api/auth.test` Bearer for `xox` tokens; webhooks unverified), **sendgrid** (guided; verify `GET https://api.sendgrid.com/v3/scopes`), **twilio**, **google**, **private-key**, **unknown**: guided with sensible guidance, unverified where needed.
- **crypto-wallet** (guided). guidance must start with: "Move funds to a new wallet first; rotating the variable does not protect funds already exposed."
- **app-secret** (generate). rotate returns `generateSecret(oldValue)`, oldRevoked false, note that sessions/JWTs signed with the old secret become invalid. verify ok.

## Wave 2

### rotate (`src/rotate/`)
`executePlan(plan: RotationPlan, inv: Inventory, deps: EngineDeps, opts: RotateOptions): Promise<RotationReport>` with

```ts
interface EngineDeps {
  hosts: Partial<Record<HostId, HostAdapter>>;
  providers: (id: ProviderId) => ProviderAdapter;
  providerCtx: ProviderContext;            // engine clones it per step with siblingVars
  journal: Journal;
  prompt: (p: GuidedPrompt) => Promise<string | null>;   // null = skip this step
  fingerprintKey: Buffer;
  redactor: Redactor;
  log: Logger;
  sleep?: (ms: number) => Promise<void>;
  now?: () => Date;
}
interface RotateOptions {
  dryRun: boolean;
  revoke: 'after-deploy' | 'immediately' | 'never';
  redeploy: boolean;            // default true
  deployTimeoutMs: number;      // default 600_000
  pollIntervalMs: number;       // default 5_000
}
```

Phases:
1. **Read current values.** For each step, read the current plaintext from the first readable consumer (re-read from the host at execution time; the inventory has no plaintext). Re-fingerprint; if it no longer matches the cluster fingerprint, warn and skip (stale inventory). Sealed clusters have no readable value: auto providers that need the old value fall back to guided.
2. **Create new credentials** in plan order: auto/atomic-roll/generate via `provider.rotate`; guided via `deps.prompt` (null → skipped). Register every new value with the redactor immediately. Verify each new value with `provider.verify`; on failure mark the step failed and do not write it (if the provider already created a key, try to revoke the new key and report).
3. **Batch writes per service**: merge every new value (and companions) for each service into one `writeVariables(service, vars, { skipDeploy: true })` call. Variable names come from each consumer's `varName`.
4. **One redeploy per service** (when the host has the redeploy capability and `opts.redeploy`), then poll `deploymentStatus` until success/failed/timeout.
5. **Revoke old keys**: per step, only if every consumer service was written, and (for `after-deploy`) every redeploy for those services succeeded. `atomic-roll` steps are already revoked. `oldKeyRef` comes from `RotationResult.oldKeyRef`, or `provider.resolveKeyRef(oldValue)` for guided steps. For revoke, pass `siblingVars` containing the service's new values.
6. **Journal** every transition (`deps.journal.append`), and return a `RotationReport`.

Dry run: phases 1 and the diff only: for each service list `VAR: <old hint> → <new>` and the redeploys that would happen. No provider or host writes.

Failure handling: one failed step never blocks other steps, but a failed host write for a service blocks revocation of every step that writes to that service. Writes that partly succeeded are reported per service. Resume: not required in v1, but the journal must contain enough (step, service, event, fingerprints) to see what happened.

### monitor (`src/monitor/`)
Public API (`src/monitor/index.ts`):
- `state.ts`: monitor state in `.keysentry/monitor.json`: per keyRef usage history (hourly buckets, 30 days), last cumulative totals, canaries, seen feed items, seen GitHub alerts, last verify results, cooldowns, pending actions, auto-rotation counts per day.
- `detectors/usage.ts`: for every inventory cluster whose provider has `usage`/`listKeys` and resolvable keyRef (via `resolveKeyRef` using a value read from a host, or a stored mapping), compute the current window's cost/requests. Baseline: median and MAD of the last 7 days of hourly buckets. Signal `usage_anomaly` when the current hour exceeds max(floorUsd (default 2), median + 8·MAD, 5× the 95th percentile), or when a model never seen for that key costs more than $1 in the window. Cold start (< 24 buckets): only the floor and an optional per-key hourly budget. Confidence: high when > 20× baseline or budget exceeded, else medium.
- `detectors/canary.ts` + `canary.ts`: `createCanary({ provider: 'openrouter', host, service, varName? })` creates a decoy key (OpenRouter `createCanaryKey`, limit $0.01), plants it in the given host service with `skipDeploy: true` under a plausible name (default `OPENROUTER_API_KEY_FALLBACK`), and records it. The detector raises `canary_triggered` (high) when the decoy's usage > 0 or it has been disabled for reaching its limit; scope = the host/service where it was planted. Also `listCanaries`, `removeCanary`.
- `detectors/breach-feed.ts`: polls configurable RSS/Atom feeds (defaults for Railway, Vercel, Render, Fly, plus GitHub's changelog security label; leave URLs in one constants table and document that they must be checked). Items whose title/summary match security keywords (`security incident`, `unauthorized access`, `breach`, `compromised`, `rotate`, `environment variables`) and that mention a host present in the inventory raise `host_breach_advisory` (medium). Dedupe by link.
- `detectors/github-leaks.ts`: for configured repos, `GET https://api.github.com/repos/{o}/{r}/secret-scanning/alerts?state=open&per_page=100`; fingerprint each alert's `secret` locally (never store it), match inventory clusters → `leak_detected` (high). Dedupe by alert number.
- `detectors/revoked.ts`: at most hourly per cluster, read the current value from a host consumer and `provider.verify` it; if it was ok last time and now fails with 401/403 → `revoked_upstream` (high).
- `policy.ts`: `defaultPolicy(): Policy` (canary_triggered → rotate/service/medium; leak_detected → rotate/cluster; revoked_upstream → rotate/cluster; usage_anomaly → cap/cluster/medium; host_breach_advisory → alert/host; autoExecute false; cooldown 60 min; max 10 auto-rotations/day) and `decide(signal, inv, policy, state): Decision[]` that expands scope to cluster ids, applies minConfidence, cooldowns and the daily cap.
- `actions.ts`: executes decisions: `alert` → notifier; `cap` → `provider.cap(keyRef)` when available else alert; `rotate`/`breach-mode` → if `policy.autoExecute`, `buildPlan(inv, { clusterIds })` then call the injected `RotateExecutor` (`(plan) => Promise<RotationReport>`; the CLI wires it to `rotate/executePlan` with `dryRun: false`, guided steps skipped); otherwise create a `PendingAction` and notify. `approve(actionId)` executes a pending action.
- `notify.ts`: `createConsoleNotifier(log)` and `createWebhookNotifier(url, http)` (POST JSON `{ text, content }` so Slack and Discord both accept it), `combineNotifiers(...)`.
- `daemon.ts`: `runMonitorOnce(ctx): Promise<{ signals: Signal[]; decisions: Decision[] }>` and `runMonitor(ctx, { intervalMs, signal?: AbortSignal })`. ctx carries inventory, hosts, providers, providerCtx, policy, state store, notifier, rotate executor, fingerprint key, log, clock.

## Wave 3

### cli (`src/cli/`), mcp (`src/mcp/`), skill, README
- `config.ts`: `keysentry.yaml` (optional) + environment. Hosts are enabled when their token env var is set (`RAILWAY_TOKEN` or `RAILWAY_PROJECT_TOKEN`, `VERCEL_TOKEN` (+ `VERCEL_TEAM_ID`), `RENDER_API_KEY`, `FLY_API_TOKEN` (+ `FLY_ORG`), `GITHUB_TOKEN` + configured repos) and dotenv roots default to `.`. Provider admin credentials come from env vars named in `PROVIDER_CREDENTIALS`.
- Commands (commander): `init` (fingerprint key, `.keysentry/`, sample `keysentry.yaml`), `scan` (writes inventory, prints blast radius), `report [--json]`, `plan [--tier …] [--cluster …] [--host …] [-o runbook.md]`, `rotate [--plan <id>|--tier …|--cluster …] [--execute] [--revoke after-deploy|immediately|never] [--no-redeploy]` (dry run unless `--execute`; interactive confirmation unless `--yes`; guided steps prompt for the new value with hidden input), `canary create|list|remove`, `monitor [--once] [--interval 300]`, `actions` (list pending), `approve <id>`, `dismiss <id>`, `drill` (timed dry run of rotating everything + a readiness score: % auto-rotatable, % sealed, duplicates, missing admin credentials), `mcp` (stdio MCP server).
- MCP tools (`@modelcontextprotocol/sdk`, stdio): `scan`, `blast_radius`, `plan_rotation`, `rotate` (dry run unless `execute: true` and `confirm: "ROTATE"`), `monitor_status`, `list_pending_actions`. Tool results never contain plaintext values.
- `skill/SKILL.md`: an agent skill telling coding agents how to use keysentry on breach night (scan → blast radius → plan → dry-run → execute with the human's confirmation).
- E2E test with fake hosts/providers covering scan → plan → rotate (dry run and execute) → monitor once with a canary hit.
