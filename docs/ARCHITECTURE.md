# keysentry architecture and module specs

keysentry is a local CLI with an optional self-hosted watcher. It finds known copies of secrets across a
team's hosts, rotates them in a safe order with one redeploy per service, verifies the new keys, revokes the old ones,
and monitors keys so it can contain or rotate them when it sees suspicious use.

The contracts every module implements are in `src/types.ts` (owned by the orchestrator; do not edit). All network
access goes through `HttpClient` (`src/http.ts`); tests use `FakeHttp` (`test/helpers/fake-http.ts`).

## Non-negotiable safety rules (every module)

1. **Never persist a secret in plaintext, and never keep one after it is needed.** Inventory, plans, journal and monitor state are encrypted with a vault-held key. New and readable old rotation values exist only in memory and the encrypted `InFlightStore`; destroy their per-plan key and remove records when the rotation or full undo finishes. Partial and grace-pending work retains recovery data. Fingerprints use keyed HMAC (`core/fingerprint`); hints expose at most seven prefix and four suffix characters for values of at least 16 characters. Logs pass through the `Redactor`. Never put secrets in argv, child-process environments, URLs, errors, the audit log or network receipt.
2. **Never delete or alter a variable keysentry was not asked to change.** Hosts whose API replaces the full set must
   read-modify-write. Railway: never `replace: true`.
3. **Dry-run is the default** for anything that writes to a host or a provider. Writes require `dryRun: false`.
4. **Revoke last.** An old key is revoked only after every consumer has the new value and (by default) the
   redeployments succeeded. Atomic-roll providers are the documented exception.
5. **No secrets in URLs or query strings.** Use headers/bodies.
6. **Fail closed.** If verification of a new key fails, stop that step, do not revoke the old key, report clearly.
7. Monitoring actions are rate-limited (cooldown per cluster, max automatic rotations per day) to prevent loops.
8. **Human approval gates mutations.** Mutation entry points refuse known coding-agent environments and require stdin/stdout TTYs, including with `--yes`. Build write-role adapters only after this check and human confirmation. Read commands use read-role credentials.
9. **All outbound HTTP is guarded.** Adapters, detectors, notifications and release verification share the injected egress-checked `HttpClient`; every attempted request records only host, purpose, method, timestamp and result metadata.

## Layout and ownership

| Path | Module | Wave |
|---|---|---|
| `src/types.ts`, `test/helpers/*` | contracts and test helpers (orchestrator) | 0 |
| `src/security/` | encryption/signing primitives and tamper-evident audit | phase 1, waves 0-1 |
| `src/vault/` | OS stores, encrypted-file/env/memory backends, credential roles and key helpers | phase 1, wave 1 |
| `src/net/`, `src/http.ts` | egress rules, guarded HTTP and network receipt | phase 1, wave 1 |
| `src/release/`, `scripts/` | local integrity, release checks and reproducible build tooling | phase 1, wave 1 |
| `src/doctor/`, `src/safety/` | capability guidance, agent refusal and Node permission re-exec | phase 1, wave 2 |
| `src/core/` | fingerprint, classify, inventory, plan/runbook, redaction/logging, state store, random | 1 |
| `src/hosts/` | host adapters: railway, vercel, render, fly, github-actions, dotenv | 1 |
| `src/providers/` | provider adapters + registry | 1 |
| `src/rotate/` | rotation engine | 2 |
| `src/monitor/` | detectors, policy, canaries, daemon, notifier | 2 |
| `src/autopilot/`, `src/feeds/` | signed armed plans, incident corroboration, scope checks, rotation waves and kill switch | phase 2 |
| `src/notify/` | signed messages, channels and delivery retries | phase 2 |
| `src/approvals/` | WebAuthn verification, action-bound approval service, relay and minimal HTTP server | phase 2 |
| `src/watcher/`, `deploy/` | sealed deployment configuration, serialized runtime, container and platform templates | phase 2 |
| `src/cli/`, `README.md` | CLI integration, configuration, prompts and e2e tests | phase 1, wave 3 |

Tests live in `test/<module>/*.test.ts`. Each module exports its public API from `src/<module>/index.ts`.

## Wave 1

### core (`src/core/`)
Public API (`src/core/index.ts`):
- `fingerprint.ts`
  - `loadOrCreateFingerprintKey(dir?: string): Promise<Buffer>` remains a 0.1 compatibility helper. Production uses `vault/fingerprintKey(vault, projectId, <userDir>/fingerprint.key)`: a project-scoped vault key, importing and deleting a legacy file only after read-back verification.
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
- `store.ts`: production uses `createStateStore({ cwd, cipher: createStateCipher(key) })` in `<cwd>/.keysentry/`. JSON records start with `keysentry-encrypted:v1` followed by base64 sealed bytes; journal lines are individually sealed with kind-specific authenticated data. The store exposes typed `writeJson`/`readJson`, inventory helpers, `journal()` and `migratePlaintext()`. A missing/wrong key raises `StateLockedError` without silently overwriting saved state. Legacy 0.1 plaintext helpers remain for compatibility tests, not CLI persistence. Files use private modes where supported and `.keysentry/.gitignore` ignores all contents.
- `inflight.ts`: `createInFlightStore({ dir, vault, projectId })` stores per-plan values under a one-time vault key. `put` fsyncs before returning; `shred` deletes the key before removing the records. A shredded plan cannot accept later values.
- CLI wraps the store journal so every event is mirrored as metadata to `security/createAuditLog`; no plaintext state/audit helper is used for production persistence.
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
  - writeVariables: Machines API `POST /v1/apps/{app}/secrets` with `{ values }` stages only selected secrets and remembers the returned secret version when available.
  - redeploy: list all Machines with full configs, then lease and update them sequentially with unchanged config, `current_version` and available `min_secrets_version`. Running Machines must confirm the new started version before continuing; stopped/suspended Machines remain stopped. Release leases even on failure. The opaque deployment ID contains only app/machine/version metadata. No Machines returns null and does not prove activation; status requires each recorded new version.
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
  inflight?: InFlightStore;
  grace?: (info: GraceInfo) => Promise<GraceDecision>;
  crashHook?: (point: CrashPoint, detail: { clusterId?: string; serviceKey?: string }) => void;
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
  graceMs?: number;            // engine default 0; CLI defaults to 120_000
}
```

Phases:
1. **Read current values.** For each step, read the current plaintext from the first readable consumer (re-read from the host at execution time; the inventory has no plaintext). Re-fingerprint; if it no longer matches the cluster fingerprint, warn and skip (stale inventory). Sealed clusters have no readable value: auto providers that need the old value fall back to guided.
2. **Create new credentials** in plan order: auto/atomic-roll/generate via `provider.rotate`; guided via `deps.prompt` (null means skip). Immediately store the new value through `inflight.put` before another awaited operation, then journal `value-stored`. Register the new value with the redactor and verify it before writing. Store readable old values before host writes. If verification fails, do not write it; cleanup/reporting preserves recovery data whenever delivery may have happened.
3. **Batch writes per service**: merge every new value (and companions) for each service into one `writeVariables(service, vars, { skipDeploy: true })` call. Variable names come from each consumer's `varName`.
4. **One redeploy per service** (when the host has the redeploy capability and `opts.redeploy`), then poll `deploymentStatus` until success/failed/timeout.
5. **Grace and revoke old keys**: default CLI grace is 120 seconds, configurable by `rotation.graceSeconds` (0 disables). After successful writes/deployments, journal deadlines and offer revoke, undo or defer on an interactive terminal. Without a callback the engine waits. Revocation re-verifies the new value; `finishRotation` also checks saved deployment success and the deadline (`early: true` bypasses only the deadline). Atomic-roll steps already invalidated the old value. `oldKeyRef` comes from `RotationResult.oldKeyRef` or guided resolution; revocation uses matching new sibling values.
6. **Journal** every transition (`deps.journal.append`), and return a `RotationReport`.

Dry run: phases 1 and the diff only: for each service list `VAR: <old hint> → <new>` and the redeploys that would happen. No provider or host writes.

Failure handling: a failed host write blocks revocation of every step delivered to that service. Partial and grace-pending reports retain encrypted in-flight records. `resumeRotation({ plan, inventory, entries }, deps, opts)` reconstructs progress, skips writes whose fingerprints already match, and polls recorded deployments. A create with no durable replacement becomes an orphan suspect; recovery never guesses which key to revoke. `undoRotation` restores saved readable old values, redeploys once per service, verifies the old key and revokes the new key last. Undo is unavailable for unreadable or invalid old values. Completion/full undo crypto-shreds in-flight data. `crashHook` is an injected test seam, not production behavior.

### monitor (`src/monitor/`)
Public API (`src/monitor/index.ts`):
- `state.ts`: encrypted monitor state in `.keysentry/monitor.json` through the supplied state store: per keyRef usage history (hourly buckets, 30 days), last cumulative totals, canaries, seen feed items, seen GitHub alerts, last verify results, cooldowns, pending actions, auto-rotation counts per day.
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

### CLI (`src/cli/`) and README

- `config.ts`: optional `keysentry.yaml` supplies scope, policy and timing; secrets have no YAML fields. Environment scope overrides remain supported. Credentials come from `createCredentialSource(vault, env)`: reads prefer dedicated `@read` entries, then base entries, then environment; writes use base entries or environment only. Register every token with the output redactor. `network.allowHosts` accepts exact DNS hostnames only, no wildcard or IP; `rotation.graceSeconds` defaults to 120.
- Bin startup alone calls `maybeReexecWithPermissions` before runtime creation: directory read access to project/user data/dotenv roots and the bundle, write access to project `.keysentry/` and user data, child processes only for vault backends needing helpers. Supported patched Node lines start at 22.23.4, 24.22.1 and 26.12.1. The HTTP guard remains the network control.
- These fixed write grants deny creation of project `keysentry.yaml` by init, dotenv updates and `plan -o` outputs outside `.keysentry/` and the user directory. `KEYSENTRY_NO_SANDBOX=1` explicitly opts out for commands needing those writes; it disables the Node filesystem/process permission layer, not guarded HTTP. Configured dotenv roots grant reads only.
- Runtime startup opens the vault (asks before encrypted-file fallback), gets the project ID, builds the encrypted store with `stateKey`, migrates plaintext 0.1 files with one notice, imports the legacy fingerprint key, creates the audit log and wrapped journal, opens the in-flight store, then configures guarded HTTP. Runtime options inject vault/inflight/audit, crash hooks, TTY flags and user directory for tests. Help, version, network and offline verification do not open the vault; audit verification can check a local chain without a vault head, with the corresponding truncation limit.
- Guard rules combine reviewed defaults, user feed hosts, user webhook hosts and `network.allowHosts`. User rules are identified as added by the user. Only configured webhook URLs are trusted URL exceptions for credential-bearing notification paths; they do not bypass host/HTTPS/redirect checks. Receipts contain no paths and retain active plus one rotated backup.
- Read commands: `init`, `scan`, `report`, `plan`, `rotate` dry run, `drill`, monitor detection, `actions`, `canary list`, `vault status|list`, `doctor [--probe]`, `network [--since <iso>]`, `audit verify`, `verify [--offline]`. Init writes local setup; scan/plan and doctor write encrypted local metadata, but do not mutate host/provider keys. Doctor probes only when requested, persisting probe fingerprints encrypted.
- Human mutation gates: `rotate --execute`, `approve`, `resume [planId]`, `finish [planId] [--now]`, `undo <planId> [--cluster <id>]`, canary create/remove with `--execute`, vault set/remove/import-env, `state reset`, and monitor startup with autoExecute or autoContain. Call `assertHumanForMutation` before opening adapters; `--yes` skips confirmation only. Rebuild write-role adapters after the human step. A local bundle mismatch blocks rotation execution; development mode gives one warning.
- `vault set <NAME> [--role read|write] [--stdin]` accepts only `CREDENTIAL_NAMES` and reads values only through hidden prompt or stdin, never argv. The strict human gate still requires stdin/stdout TTYs with `--stdin`, so ordinary command-line pipes are refused. Embedding/tests can inject explicit TTY capability flags; this is not a normal CLI bypass. Status/list disclose names/backend/weakness only. Import copies present environment credentials and explains they can be removed from the environment.
- `state reset` requires typing `RESET`, refuses partial/grace-pending in-flight work unless forced, removes encrypted state/in-flight records, keeps the audit log and appends a reset event.
- Audit mirrors journal event names and plan/cluster/service IDs, scan counts, saved plan ID/step count, approvals, vault names/roles, doctor runs and state reset. Network blocks stay in the receipt. Checkpoint after each command that appended an event. Checkpoints are device-signed and vault-anchored; local-chain verification alone cannot detect all tail truncation.
- Runtime writes a public presence marker at `<userDir>/audit-heads/<hash>.json`. Its presence triggers vault-anchor lookup even if the project log has been removed. When both marker and log are absent and no vault is injected, verification reports local-chain verification only with the independent head unchecked. The env backend cannot persist a head: signed checkpoints remain verifiable, but heads are process-local, a warning is emitted, and no durable tail-truncation check is available across processes.
- `verify` first checks local manifest consistency, then published signed checksums online through guarded HTTP. Empty release public keys produce `unconfigured`, not a verified publisher. Current output states: `Release signing keys are not published yet; only the local check ran.` Source checkouts report development integrity. Provenance verification is not implemented in this phase.
- E2E tests inject fake vaults, HTTP, hosts/providers and temporary directories; no real credential-store helper or network request is used. Cases cover encrypted persistence/audit, receipt hosts, agent refusal, hidden vault input, grace/finish, crash/resume and 0.1 migration.

## Phase 2: breach autopilot and watcher

### Authorization and scope (`src/autopilot/`)

`autopilotEligibility` uses the actual provider capabilities and the existing exact-name generate rule. Payment,
database, encryption, wallet/private-key, guided and atomic-roll credentials are excluded. Write-only consumers
need supervised adoption before automatic coverage. Adoption stores the replacement fingerprint, provider key
reference and time in `ArmedCluster.adopted`; its plaintext is not retained as authorization material.

`buildArmedPlan` captures all consumers of selected eligible clusters, including consumers on other hosts. The
plan binds the project, incident hosts, permitted methods, fingerprints, maximum service count, health checks,
grace period, expiry and explicit next-deploy acceptance. Defaults are 10 services, 900 seconds and 90 days;
validity is capped at 365 days. `signArmedPlan` signs the canonical document, including its signer, with the
`keysentry-armed-plan:v1\n` domain prefix. `verifyArmedPlan` validates the strict schema, Ed25519 signature,
trusted key ID and current time. Verification precedes every automatic boundary.

`checkScope` compares the signed document with fresh inventory. Added/removed consumers, changed fingerprints,
an uncovered host, ineligible methods and a wave exceeding its signed service limit become approval requests.
`arm` requires a successful drill from the last 24 hours and signs the selected authorization locally. Both the
drill record and `armed-plan.json` are encrypted state; the latter uses StateStore kind `plan`. Re-arming replaces
the authorization and appends an audit event. Non-secret defaults are YAML `autopilot` settings, not doctor state.

After adopted-key rotations, the runner returns `adoptionUpdates`. The local CLI can apply updates in its own
state store and re-sign with the device key. A watcher cannot forge a device authorization: it retains the updates
and reports `re-arm to refresh adopted keys`. Local `arm --refresh` reviews and signs updates for the same CLI/local
`watch` store; it does not import updates from a separate deployed watcher. Remote renewal must reconcile the
original watcher's encrypted state and matching keys before re-arming. Remote update export/import and dashboard
reconciliation remain phase 3 gaps. Manual rotations must also apply adoption updates before treating the old
authorization as current.

### Sources and incident decisions (`src/feeds/`, `src/autopilot/{sources,incidents}.ts`)

`fetchFeed` uses the guarded client, conditional cache headers and bounded RSS/Atom parsing. Recorded evidence
contains sanitized metadata and keyed item identities, never application key values. The source table records
official/news classification, platform coverage and publisher ownership. One high-confidence official advisory
can trigger; an official source plus credential-exposure news, or two independent news owners describing the
same platform's credential exposure within the allowed window, can corroborate. One report alone alerts and
requests approval. News naming a platform without credential exposure does not trigger rotation.

Incident state is encrypted and persisted before its effects. One platform incident per seven-day window avoids
repeated waves; a triggered incident does not trigger again. Each watcher fetches evidence itself rather than
accepting a central rotation instruction. Feed text remains untrusted even when its host is allow-listed.

### Wave execution (`src/autopilot/runner.ts`, `src/rotate/`)

`runAutopilot` creates one `wave-<incidentId>` with the original inventory, rotation plan and signed authorization
saved before execution. It forces serial deployments, verify-before-write, stop on first failure, a wave-wide
revocation hold, and deferred grace. Signed health checks use the guarded HTTP client: three probes 20 seconds
apart after deployment and again before deferred revocation. No provider diagnostics or response bodies become
notification content. The runner's start/failure/grace/end messages contain counts; hints are separately opt-in.

`resumeWaves` continues saved interrupted work. Before `settleWaves`, CLI wiring rescans using read-role tokens
and supplies the fresh inventory, so a newly discovered consumer cannot be missed by a saved scan. Recovery
revalidates authorization and scope. Disarmed/alert-only state prevents automatic recovery and settlement.
Next-deploy consumers retain old keys unless signed maximum-deadline consent permits revocation; early
next-deploy detection is not implemented. Failed waves need human remediation. Interrupted settlement can leave
some old keys revoked, which is reported rather than claiming the whole wave remains reversible.

### Signed notifications (`src/notify/`)

The CLI constructs Telegram, Discord, Slack, ntfy, webhook, Resend, SMTP and console channels. YAML `notify`
contains channel IDs, kinds and non-secret server/address settings. Secret fields use vault names
`notify/<channelId>/<field>`; webhook URLs, bot/API tokens, SMTP passwords and topics never enter YAML. Each
configured HTTP destination becomes an explicit user egress rule and trusted URL entry where required by
credential-bearing service paths. Health hosts are user rules with purpose `health check you configured`.
SMTP uses TLS/STARTTLS with certificate verification and records a metadata-only `smtp:<host>` receipt entry.

`signMessage` signs canonical messages with `keysentry-notify:v1\n`; the short base32 verification code derives
from the signature. `verifyMessage` requires the full signed object and trusted public key. The CLI verifies a
cached message by code or a full JSON file against its device/configured watcher keys. Generic webhook delivery
preserves the signed JSON and adds signature headers; text channels show the code. Secret checks reject a
message rather than changing its signed content. The dispatcher retries individual channels and records actual
successful delivery, which the watcher persists for its notification dead-man check.

### Approvals and local registration (`src/approvals/`, `src/cli/`)

The encrypted approval store binds each action ID to one digest and a random challenge. Requests expire after
ten minutes, are single-use and limit failed attempts. WebAuthn accepts supported COSE keys, validates exact RP
and origin, requires user verification, checks counters and rejects clone warnings. Device approvals sign
`keysentry-approval:v1\n` plus `{ actionId, digest, at }`; signed disarms use their separate domain prefix.
The relay verifies configured trusted keys and freshness. Its topic is not authorization; ntfy.sh topics can be
public read/write. A relay may delay or suppress a valid message and cannot re-arm the watcher.

`passkey register` binds a temporary server to `127.0.0.1` but opens `localhost` at a random port, with RP ID
`localhost`, a one-time URL token, exact Host/Origin checks, strict CSP and a bundled static script. It shuts
down after success, five minutes or Ctrl-C. Public-origin enrollment must happen on that origin; the current
approval server has no `/register` route and dashboard enrollment remains phase 3. Arming and channel/passkey
changes are local human mutations; remote approval cannot widen policy.

The minimal approval server exposes health, approval challenges/assertions and disarm only. It checks exact
Host and POST Origin, caps requests, rate-limits callers and serves no secret values. HTTPS termination and
trusted-proxy configuration belong to deployment. A disarm needs no passkey, stops new automatic effects and
settlement, and cannot restore a completed revocation. `KEYSENTRY_ALERT_ONLY=1` forces the same automatic hold.

### Watcher runtime (`src/watcher/`, `src/cli/`, `deploy/`)

Locally `watch` uses the CLI vault and encrypted state. Container setup seals an authenticated config containing
the signed plan and required runtime settings. `KEYSENTRY_WATCHER_KEY` opens it; `KEYSENTRY_STATE_KEY` and
`KEYSENTRY_VAULT_PASSPHRASE` protect persistent runtime data. The additional encrypted
`KEYSENTRY_WATCHER_VAULT` bootstrap blob supplies the selected host/provider tokens, scope, fingerprint and signing
material not present in the fixed `WatcherConfig` interface; its state/deployment unlock keys remain external.
All five generated values belong in platform secret settings, including the extra portable-vault variable when
using templates that list only the four core variables. Setup prints secrets only once to an interactive
TTY, never JSON. The sealed config comes from `KEYSENTRY_WATCHER_CONFIG` or
`KEYSENTRY_WATCHER_CONFIG_FILE`. Keys and passphrases stay outside `KEYSENTRY_STATE_DIR` (`/data` in the image).
POSIX state directories require mode 0700. All vault/state/in-flight/audit paths must resolve under that volume.

Setup creates a new deployment key, state key, vault passphrase and portable-vault identity on every invocation;
it does not migrate an existing live volume. Deployment renewal first uses the original matching vault, keys and
encrypted state to finish or undo pending grace/stopped rotations and reconcile remote adoption updates. Then
disarm and stop the old watcher, retain a secure backup of its unchanged encrypted volume with original keys
protected separately for recovery/audit, and prepare the new setup against a fresh private directory or volume.
Supply all five new secret settings to the replacement. Leave the old volume unchanged; a new key/passphrase must
not be substituted against it. Unlock keys remain outside state. There is no phase 2 live-state migration or
remote adoption export/import flow; the later dashboard must address that reconciliation explicitly.

The serialized tick resumes waves, polls the relay, reads sources, persists incident decisions, handles waves
and approval requests, settles grace, runs detectors and sends a daily heartbeat. Persisted acknowledgments and
the original start/delivery anchors survive scheduled restarts. No successful notification for 24 hours, invalid
authorization, unwritable state or clock skew beyond 300 seconds forces alert-only. The watcher excludes its own
operating credential names from automatic work; an incident on its own platform requests guided rotation.

`watch --once` provides scheduled execution with a fresh safety check before its final settlement. Templates
cover Railway, Fly, Render, Docker Compose and Actions; they do not deploy automatically. The container runs
non-root with a read-only root and a private writable state volume. Image publication/digests, live platform
permissions and browser ceremonies remain release integration checks. Actions scheduling delay, dropped runs
and cache eviction are operational limits, not a real-time guarantee.
