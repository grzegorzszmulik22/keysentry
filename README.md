# keysentry

Find the same secret across deployment hosts, plan its rotation, update every known consumer, redeploy each affected service once, and revoke the old key after successful deployment. keysentry is a local CLI for routine rotation and monitoring.

> **Status: phase 1 of keysentry 1.0: trust foundation.** Adapters are tested against fakes built from vendor documentation, not yet against live accounts. Native vault helpers are also tested through fakes. Try dry runs and a drill on a staging project before relying on provider writes. Dashboard, passkey arming, cloud boxes and the token-free onboarding wizard are later phases. Release signing keys are not published yet.

## The trust promise

The [1.0 design](docs/superpowers/specs/2026-10-27-trust-autopilot-design.md#3-the-trust-promise) sets this promise. The status above and the limits below distinguish the current phase from planned releases and cloud features.

1. **No AI touches your keys.** keysentry is plain code making documented API calls. No model, agent or MCP server
   is part of it.
2. **Your keys stay with you.** Self-hosted: on your machine and in your own cloud; keysentry the company never
   receives them. Cloud box: decrypted only inside a confidential machine running the published open-source build,
   which you can check (exact wording and limits in §7.10).
3. **Read-only until you say otherwise.** The first run needs no tokens at all. Until you approve a change, keysentry
   makes only read calls; it uses read-only tokens wherever the platform offers them, and `doctor` shows exactly what
   each token you gave it could do. (Several platforms, for example Vercel, Railway and Render, offer no read-only
   token that can read variable values, so the promise is about what keysentry does, not what the token allows.)
4. **Nothing changes without your OK**, except rotations you armed in advance for autopilot, and you can see and
   change exactly what those are at any time.
5. **No telemetry, no account, no phoning home.** `keysentry network` shows every host it has ever contacted and why.
6. **Open source with signed, reproducible releases.** You can rebuild the release and get the same bytes, and
   `keysentry verify` checks the copy you installed.
7. **Every action is recorded** in a tamper-evident log that you hold.

The current receipt keeps a bounded local history, rather than an unlimited record of every contact. `verify` cannot authenticate a release until public signing keys are configured. The CLI has no model integration; agent detection adds a check for known environments, but cannot identify an agent that removes its markers or protect against other programs running as your user.

## Run from this checkout

Requires Node.js **22.13 or newer** and the installed project dependencies. The optional Node permission sandbox requires a patched supported release: **22.23.4, 24.22.1 or 26.12.1 or newer within those major lines**. Older or unsupported Node releases run without that additional sandbox; the HTTP allow-list still applies.

The sandbox grants writes to the project's `.keysentry/` directory and the user data directory. `init` also receives the config file path, and `plan -o` receives its output file path. Executing commands receive the configured dotenv consumer files from the inventory, plus their temporary-file prefixes for atomic replacement. If the inventory cannot be read yet, those commands receive the configured dotenv roots instead. Sandbox status comes from Node's permission API.

```sh
npm run build
node dist/cli/index.js --help
```

The examples below use `keysentry` for the package CLI. From this checkout, substitute `node dist/cli/index.js` or `npm run dev --` for `keysentry`. A public one-command package onboarding flow is planned for phase 3. This checkout is licensed under [Apache-2.0](LICENSE).

## Quick start

Run these from your project in a normal terminal:

```sh
keysentry init
keysentry vault import-env
# Or save a particular credential through hidden input:
keysentry vault set RAILWAY_TOKEN
keysentry scan
keysentry plan
keysentry rotate
```

Use either environment import or individual `vault set` commands. `init` creates project state and a sample configuration without overwriting an existing config. A local dotenv scan needs no host token. `scan` saves an encrypted inventory and prints the blast radius, including hosts it could not scan. `plan` saves an encrypted ordered plan and an optional readable runbook. `rotate` previews changes without writing to hosts or providers.

Review the dry run, then run `keysentry rotate --execute` yourself. It prints the diff and requests the number of secrets before proceeding. `--yes` skips that question, but every mutation still requires an interactive human terminal and refuses known coding-agent environments. Use `--plan <id>` to execute a saved plan, or `--tier cloud,ai`, `--cluster <id>`, and `--host <id>` to narrow selection. Selecting a shared secret retains all known consumers, including those on other hosts.

Guided providers show their dashboard and instructions, then request the replacement through hidden input. Use bracketed paste for multi-line PEM or JSON values, or enter `@<path>` to read a value from a file. File input removes one trailing newline. Input is not echoed. Delete any temporary secret file after use. Empty input skips the step; Ctrl-C or Esc aborts the rotation before further changes.

Global flags are `--cwd <dir>`, `--config <path>`, `--json`, and `--verbose`. Config defaults to `keysentry.yaml` in the selected directory. JSON output excludes plaintext values. Errors use exit status 1; `scan --fail-on-findings` uses 2 for findings requiring attention. A partial scan does not establish that a host is clear. Plans touching a host with scan errors are blocked; unrelated plans may proceed with a warning.

## Vault and credential roles

Tokens and keysentry's encryption/signing keys live in macOS Keychain, Windows current-user DPAPI, or Linux Secret Service. If an OS store is unavailable, keysentry asks before using a passphrase-protected encrypted file in `~/.keysentry/`. It remembers the backend in `~/.keysentry/vault-backend.json`, so returning to a desktop terminal does not switch key sets. If an older installation has an encrypted file and an available OS store without a remembered choice, it asks which to use; non-interactive runs use the file with a warning. A new file asks for the passphrase twice. Linux Secret Service needs `secret-tool` (usually the `libsecret-tools` package) and a session bus.

```sh
keysentry vault status
keysentry vault list
keysentry vault set GITHUB_TOKEN --role read
keysentry vault set GITHUB_TOKEN --role write
keysentry vault remove GITHUB_TOKEN --role read
```

`status` shows the backend, any weakness, and credential names by role. `list` shows names only. `set` never accepts a token argument; use its hidden prompt. With explicit `--stdin`, a human may pipe one value from their terminal while stdout remains a TTY. Without `--stdin`, both input and output must be TTYs. Known coding-agent environments are refused in either case. The default role is `write`. Use only the supported host and provider credential names listed in the tables below. `vault import-env` copies present credentials into the vault; they can then be removed from the environment.

Scanning, reports, plans, drills and monitor detection use read-role credentials. Reads fall back from the dedicated read token to the base token, then the existing environment variable. Approved mutations rebuild adapters with the write token; they never substitute the dedicated read token for writes. A role name does not reduce a token's actual vendor permissions: `doctor` explains those limits.

Existing credential environment names still work. Explicit `KEYSENTRY_VAULT=env` is read-only and needs keysentry's encryption/signing keys supplied separately; `doctor` explains missing settings. `KEYSENTRY_VAULT=encrypted-file` selects the file store. Non-interactive file-store reads use `KEYSENTRY_VAULT_PASSPHRASE`. Environment and memory backends keep in-flight rotation values only for that process and cannot provide recovery after it exits; executing commands and doctor warn about this. Environment-backed project bindings and initialization markers are also process-local unless supplied in the environment. OS stores and the encrypted file protect data at rest; other programs running as your user can still request or use credentials.

## Doctor

```sh
keysentry doctor
keysentry doctor --probe
```

The default check is local: vault backend, token capability guidance, local bundle integrity and Node sandbox status. `--probe` makes the documented account checks through the guarded HTTP client, including GitHub scopes when configured. Probe fingerprints are stored in encrypted state so a later run can report changes. Capability guidance is based on vendor documentation; a local check alone does not prove the exact permissions of a particular account token.

## Network receipt

```sh
keysentry network
keysentry network --since 2026-10-27T00:00:00Z
```

The command lists allowed hosts grouped by purpose, labels rules added by you, then summarizes requests, blocked requests and last contact. The receipt contains hostnames and purposes, never URL paths, queries, headers or bodies. It keeps the active log and one rotated backup; older history is replaced.

All HTTP uses the injected guarded client: HTTPS only, approved hostnames, bounded responses, and redirects checked against the same rules. Configured feeds and notification webhooks add explicit rules. Add a custom HTTPS service hostname, such as a Supabase custom domain, with `network.allowHosts` in [keysentry.example.yaml](keysentry.example.yaml). Entries must be exact DNS hostnames; wildcards and IP addresses are refused. Local HTTP endpoints remain blocked. Dotenv scanning makes no network requests. `network`, help and version output do not open the vault.

## Verify and audit

```sh
keysentry verify --offline
keysentry verify
keysentry audit verify
```

The offline command compares the bundle with its adjacent local manifest. The online command additionally checks published signed checksums through the guarded client. A local manifest comparison checks consistency, not who published the files. Run verification from an independently obtained copy, such as a fresh `npm pack` of the published version: a modified bundle can lie about its own checks. Source checkouts are reported as development builds. Until signing keys are published, online verification prints: `Release signing keys are not published yet; only the local check ran.` A local bundle mismatch blocks `rotate --execute`; a missing manifest warns and requires typing `yes`, including with `--yes`.

`.keysentry/audit.jsonl` records metadata for scans, saved plans, approvals, vault changes, doctor runs, state resets and every rotation journal event. Every hash-chain record has an HMAC under a vault-held key, and checkpoints are signed; registered secrets are redacted. Forged appends require the vault MAC key. The saved vault head detects truncation behind the last checkpoint; an uncheckpointed suffix can still be removed. `audit verify` always consults the vault for this log path and returns exit status 1 for a failed MAC, a changed chain, or a nonempty log without an anchor. The audit log remains after a state reset.

Public markers under `~/.keysentry/audit-heads/` are hints only; removing one never skips the vault lookup. The environment vault cannot persist audit heads, so a later `audit verify` refuses a nonempty unanchored log. Its audit MAC key is process-local unless `KEYSENTRY_VAULT_AUDIT_MAC` supplies the same 32 UTF-8 bytes on every run. These backends provide no durable tail-truncation check across runs.

## Resume, undo and finish

```sh
keysentry resume                  # latest unfinished plan
keysentry resume <plan-id>
keysentry undo <plan-id>          # restore readable old values during grace
keysentry undo <plan-id> --cluster <cluster-id>
keysentry finish                 # latest unfinished plan, after its deadline
keysentry finish <plan-id> --now  # settle early, with the same safety checks
```

The default grace period is 120 seconds; set `rotation.graceSeconds` to change it, or `0` to disable it. After new keys are active, the terminal offers Enter to revoke now, `u` to undo, or `l` to leave old keys valid and finish later. At the deadline, keysentry re-verifies before revocation. `finish --now` bypasses the deadline only: it still checks the new key and recorded deployment results.

New and readable old values are encrypted in `.keysentry/inflight/` under a per-plan vault key. Completion or full undo destroys that key and deletes the records; partial and grace-pending runs retain them for recovery. `resume` uses the saved plan, inventory and encrypted journal to continue an interrupted run. If a provider created a key before keysentry could save it, recovery reports a possible unrecorded key and does not guess which key to revoke. Inspect the provider dashboard in that case.

Undo needs a readable saved old value and a still-valid old key; sealed values may make it unavailable. Atomic rolls invalidate the old key immediately and offer no overlap. An interactive recovery prompt may offer the new atomic-roll value once after the exact response `SHOW`; keep that terminal private. Recovery is not a cross-host transaction or a guarantee that every application supports reversal.

`keysentry state reset` requires typing `RESET`. It deletes encrypted state and in-flight records, keeps the audit log, and records the reset. It refuses to discard in-flight values from partial or grace-pending plans unless `--force` is supplied; forcing reset gives up that recovery data.

If the state key is lost, an interactive `scan` asks before replacing unreadable inventory and monitor state with a fresh scan. It keeps saved journals, plans and in-flight records. Non-interactive scans refuse and point to `keysentry state reset`. Losing the audit key separately prevents extending or authenticating the old audit log; restore that vault key before continuing.

## Using keysentry with AI coding tools

Your coding agent may suggest commands and, at your request, run read-only `scan`, `report`, `plan` and dry runs. Their output contains fingerprints, short hints and metadata, not key values. Review the output and run changes yourself in a normal terminal.

keysentry refuses known agent environments for key changes, dismissing pending actions, recovery commands, vault changes, state reset and monitoring configured for automatic actions. These commands also require an interactive terminal, even with `--yes`; explicit `vault set --stdin` permits piped input with terminal output. This keeps a model-generated suggestion from becoming approval to change your credentials. Marker detection is an additional check, not a guarantee against software that hides its identity.

## Configuration and supported hosts

`keysentry init` creates project metadata, vault-backed keys and a sample config without overwriting existing configuration. YAML is optional. Environment scope settings override corresponding YAML settings; credentials resolve through the vault roles described above. A missing token disables that host and is reported during scan. dotenv scanning defaults to the selected working directory.

| Host | Required credentials | Scope settings | Read/deploy behavior |
|---|---|---|---|
| Railway | `RAILWAY_TOKEN` or `RAILWAY_PROJECT_TOKEN` | `hosts.railway.projectIds`; `RAILWAY_PROJECT_IDS` | Readable and sealed variables; shared environment variables included; one deployment per service when supported |
| Vercel | `VERCEL_TOKEN` | `VERCEL_TEAM_ID`, `hosts.vercel.targets` / `VERCEL_TARGETS` | Readable and sensitive variables; production redeploys; preview/development apply on their next deployment |
| Render | `RENDER_API_KEY` | Accessible services | Readable variables; explicit service redeploy |
| Fly | `FLY_API_TOKEN` | `FLY_ORG` or `hosts.fly.apps` / `FLY_APPS` | Sealed values; stages updates; manually run `fly secrets deploy -a <app>` |
| GitHub Actions | `GITHUB_TOKEN` and configured repositories | `hosts.github.repos` / `GITHUB_REPOS` | Repository secrets are sealed; encrypted writes apply to the next workflow run |
| dotenv | None | `hosts.dotenv.roots` / `KEYSENTRY_DOTENV_ROOTS` | Local `.env` and `.env.*` files; no application restart |

List environment settings are comma-separated. Use YAML `enabled: false` to exclude a host. `FLY_API_TOKEN` without `FLY_ORG` or configured app names disables Fly with a scope message. Template dotenv files are excluded unless `includeTemplates: true`. Scanning skips `.git`, `node_modules`, build output, and `.keysentry`.

## Supported providers

`auto` creates an overlapping replacement, `atomic roll` invalidates the old value immediately, `generate` creates a local random value, and `guided` asks a human to create a replacement. Management credentials are separate from the application secrets being rotated.

| Provider | Rotation method | Credentials or prerequisites |
|---|---|---|
| OpenAI | auto | `OPENAI_ADMIN_KEY` with project/key management access; old key must resolve uniquely |
| OpenRouter | auto | `OPENROUTER_PROVISIONING_KEY`; old key must resolve uniquely |
| Resend | auto | Full-access `RESEND_ADMIN_KEY`; delete the old key manually when its ID cannot be resolved |
| AWS | auto | Existing IAM user access ID and secret in matching sibling variables, create/delete-key permissions, and an available second key slot; temporary session credentials cannot be automatically converted |
| Cloudflare | atomic roll | `CLOUDFLARE_ADMIN_TOKEN` with API Tokens Write; requires an interactive terminal and immediately invalidates the old token |
| Allow-listed self-issued application/session/JWT secrets | generate | No admin credential; signed sessions become invalid; `--no-generate` skips these steps |
| Data-encryption keys (`encryption-key`) | guided | Plan and complete a data migration; a random replacement can make existing data unreadable |
| Anthropic | guided | Human console access; `ANTHROPIC_ADMIN_KEY` enables key lookup, deactivation, and usage monitoring |
| Stripe and webhook signing secrets | guided | Human dashboard/endpoint access; application key is used for available verification |
| GitHub tokens | guided | Human token-management access; application token is used for verification |
| Supabase | guided | Human project access; sibling `SUPABASE_URL` enables verification; legacy JWT signing changes can affect sessions and other keys |
| Database credentials/URLs | guided | Database administrator access; change the database password before replacing its connection URL |
| Slack | guided | Workspace/app administration; token verification where available; webhooks are unverified |
| SendGrid | guided | Human API-key administration; application key is used for verification |
| Twilio | guided | Human console access; application-specific verification required |
| Google credentials | guided | Human Cloud Console/service-account administration; application-specific verification required |
| Private keys | guided | Issuer/owner access and a certificate or trust-distribution procedure |
| Crypto wallets | guided | Move funds to a new wallet first; replacing a variable cannot protect already exposed funds |
| Unknown secrets | guided | Identify the issuer and every consumer before replacement |

Verification differs by provider. Some read endpoints accept restricted credentials but return limited access; some credential types have no safe verification endpoint. Provider permissions, endpoint behavior, and account scope must be checked for the target account. See module notes under [notes/](notes/) for API assumptions and gaps.

## Peacetime setup

Initialize once, scan regularly, and plant an OpenRouter canary in a service that does not use the decoy variable:

```sh
keysentry init
keysentry scan
keysentry canary create --host railway --service <service-id> --var OPENROUTER_API_KEY_FALLBACK
keysentry canary create --host railway --service <service-id> --var OPENROUTER_API_KEY_FALLBACK --execute
keysentry canary list
keysentry monitor --once
keysentry monitor --interval 300
```

Canary creation is a dry run without `--execute`. A real canary uses `OPENROUTER_PROVISIONING_KEY`, creates a decoy with a $0.01 limit, and stages it without redeployment. Select a full service key when a service ID or name is ambiguous. Canary use or apparent exhaustion raises a signal for the planted service. Keep the decoy out of legitimate traffic. `keysentry canary remove <id> --execute` revokes the key and removes monitoring metadata; the inert variable remains because host adapters have no delete-variable operation.

Run one monitor per working directory. Ctrl-C ends the loop cleanly. Default rotation and containment decisions wait in `keysentry actions`; inspect them, then use `keysentry approve <id>` or `keysentry dismiss <id>`.

`approve` prints the planned action, whether revocation despite unconfirmed activation applies, and services needing a manual restart or future deployment. Review this output, then type the exact action ID to execute it. `keysentry approve <id> --yes` skips this confirmation; approval always needs a human at an interactive terminal and refuses known agent environments. On a terminal, approval uses the same hidden replacement input and guarded recovery reveal as `rotate --execute`.

Automatic rotation is opt-in through `monitor.autoExecute: true` or `KEYSENTRY_AUTO_EXECUTE=true`. Starting monitoring with either automatic rotation or automatic containment enabled requires a human at an interactive terminal; known agent environments are refused. Detection uses read credentials and approved automatic actions use write credentials. Unattended monitoring excludes atomic-roll, guided, and generated replacements from automatic execution and alerts for human intervention. Atomic rolls must be executed interactively. Incomplete actions remain available for human remediation.

Run `keysentry drill` periodically. It times a dry run of rotating the inventory and reports a 0–100 readiness score with reasons: automatic rotation coverage, sealed findings, duplicate clusters, missing management credentials, hosts without redeployment support, and canary coverage. The score measures preparation; a dry run does not test real provider writes or application recovery.

### Monitoring signals and default policy

| Signal | Detection | Default action |
|---|---|---|
| `canary_triggered` | Decoy spend or apparent limit exhaustion | Rotate every secret used by the planted service; minimum medium confidence |
| `leak_detected` | Configured GitHub secret-scanning alert matches an inventory fingerprint | Rotate the matching cluster; high confidence |
| `revoked_upstream` | A previously working credential becomes authentication-invalid | Rotate the matching cluster; high confidence |
| `usage_anomaly` | Spend above baseline/budget, or an expensive previously unseen model | Cap/disable the matching key where supported; minimum medium confidence |
| `host_breach_advisory` | Host-related security keywords in configured RSS/Atom feeds | Alert about the host; minimum medium confidence |

Automatic rotation defaults off, with a 60-minute per-cluster cooldown and a limit of 10 automatically rotated clusters per UTC day. Automatic containment also defaults off: enable it separately with `monitor.autoContain: true` or `KEYSENTRY_AUTO_CONTAIN=true`. `monitor.containCooldownMinutes` defaults to 60. Containment can disable a provider key and break consumers; Anthropic containment deactivates the key. Leave both automatic settings false for human approval of writes.

`monitor.revokeUnconfirmedOnHighConfidence` defaults to true; `KEYSENTRY_REVOKE_UNCONFIRMED_ON_HIGH_CONFIDENCE` overrides it with `true` or `false`. For high-confidence canary, leak, or upstream-revocation signals, automatic execution or later approval can revoke the old key despite unconfirmed activation, to stop use of a compromised key. Approval shows when this policy applies and lists consumers needing a manual restart or future deployment; those consumers can break until activated. Set it to false to retain old keys until activation is confirmed. This setting does not enable automatic rotation by itself.

Usage baselines use seven days of hourly history, retaining 30 days. Once a baseline exists, the default threshold is the maximum of $2, median + 8 × MAD, and 5 × the 95th percentile; a previously unseen expensive model may also raise a signal. Explicit hourly budgets can alert during baseline collection. OpenAI/Anthropic costs are local estimates, not billing figures; unknown models use conservative fallback rates. Cumulative counters establish a baseline on first observation and account for time between polls.

Console notifications are enabled; `monitor.webhooks` or `KEYSENTRY_WEBHOOK_URL` add Slack/Discord-compatible webhook notifications. Treat webhook URLs as credentials. Configure `monitor.feeds: []` to disable external advisory feeds. The bundled feed URLs and security keyword matching are advisory, can produce false positives, and need operator verification. GitHub alerts require `monitor.github.repos`, `GITHUB_TOKEN`, and suitable token permissions/account support; the Actions-host repository list does not enable alert polling by itself.

## Safety model and limitations

- **Local first:** `.keysentry/` holds encrypted inventory, plans, rotation journal and monitor state, plus the metadata-only audit log and network receipt. It has an ignore-all `.gitignore`; files use private modes where the OS supports them. Encryption and fingerprint keys live in the vault. Hosts/providers still receive the API calls needed for their operations.
- **Fingerprints rather than values:** readable values are HMAC-fingerprinted; hints reveal at most seven prefix characters and four suffix characters for sufficiently long values. Output passes through redaction. Rotation briefly handles plaintext in memory and sends new values to intended hosts; dotenv files necessarily contain the application's actual values.
- **Dry run by default:** rotation and canary mutations require `--execute`. Rotation requests numeric confirmation; pending-action approval requests the exact action ID. `--yes` skips those questions but preserves the human-terminal and agent checks. Monitor policy and pending-action approval are separate explicit paths to execution.
- **Verify and revoke last:** replacement verification precedes batched writes. Default revocation waits for every consumer write and confirmed activation. For overlapping replacements, failed writes/deployments retain the old key. Cloudflare's atomic roll invalidates the old token immediately and cannot provide overlap. CLI `--revoke immediately` revokes after writes but before deploys; `--revoke never` retains old keys. `--no-redeploy` cannot establish activation. Review `--revoke-unconfirmed` separately before allowing revocation without activation proof.
- **Known consumers only:** sealed secrets cannot be deduplicated by value or automatically resolved from a fingerprint. Unplanned sealed findings with a matching provider or variable name can block revocation or atomic rotation unless `--accept-unplanned-sealed` explicitly accepts the risk. Missing credentials, inaccessible services, ignored files, and out-of-scope accounts leave gaps. Stale inventory is checked before execution, but APIs do not provide cross-host transactions or compare-and-swap.
- **Activation is host-specific:** dotenv writes require a manual process restart; Fly requires manual activation; Railway shared variables and unpollable initial deployments need human verification; Vercel preview/development and GitHub Actions apply on future runs. These writes report `unconfirmed` activation and retain old keys by default. A null deployment ID is not proof of application activation.
- **Recovery has limits:** encrypted in-flight values and the journal support resume and grace-period undo. A provider can create a credential before keysentry records its value; cleanup may require its dashboard. Undo may be unavailable for unreadable old values. Run one rotation/monitor process per project; this is not an interprocess execution lock. Notification failures have no durable retry queue.

## Development checks

```sh
npx tsc -p tsconfig.json --noEmit
node tools/vitest-sandbox.mjs test
```

Tests use injected fake vaults, hosts/providers and HTTP responses. The sandbox runner executes the suite without esbuild child-process startup. No real keychain, provider account or network request is needed for these tests. Release builds and real OS-store checks are separate integration work; see [SECURITY.md](SECURITY.md) and [docs/ACCESS.md](docs/ACCESS.md).
