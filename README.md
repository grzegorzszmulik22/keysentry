# keysentry

Find the same secret across deployment hosts, plan its rotation, update every known consumer, redeploy each affected service once, and revoke the old key after successful deployment. keysentry is a local-first CLI and stdio MCP server for breach response and routine monitoring.

It groups readable secrets by keyed fingerprint, so one credential reused under several variable names becomes one rotation step. Sealed values remain visible as separate findings. Inventories, runbooks, reports, journals, and monitor state contain fingerprints, short hints, and metadata rather than secret values.

## Status

All adapters are tested against fakes built from the providers' documentation. None has yet been exercised against live accounts. Run `rotate` dry runs and a drill on a staging project before relying on keysentry.

## Run from this checkout

Requires Node.js 20 or newer and the installed project dependencies:

```sh
npm run build
node dist/cli/index.js --help
```

The examples below use `keysentry` for the package CLI. From this checkout, substitute `node dist/cli/index.js` or `npm run dev --` for `keysentry`.

Supply host tokens and provider management credentials through your environment or a trusted secret manager. Avoid putting their values in shell history. The optional [keysentry.example.yaml](keysentry.example.yaml) shows scope, rotation, and monitoring settings; credentials do not belong in YAML.

## Breach-night quick start: five commands

With credentials already available in the environment, run these from the project being investigated:

```sh
keysentry scan
keysentry report
keysentry plan -o rotation-runbook.md
keysentry rotate
keysentry rotate --execute
```

`scan` saves a fresh inventory and prints the blast radius, including missing-token hosts. `report` reviews that inventory. `plan` saves an ordered plan and a readable runbook; `rotate` previews the proposed changes without provider or host writes. `rotate --execute` prints the diff again and requires typing the number of secrets before proceeding. Use `--plan <id>` to execute a particular saved plan, or `--tier cloud,ai`, `--cluster <id>`, and `--host <id>` to narrow the selection. Selecting a shared secret retains all of its known consumers, including consumers on other hosts.

Guided providers show their dashboard and instructions, then request the replacement through hidden terminal input. Use bracketed paste in a supporting terminal for multi-line values, or enter `@<path>` to read a value from a file. Bracketed paste normalizes CRLF and lone CR line endings to LF. Multi-line input must parse as a PEM private key, PEM certificate, or JSON; other multi-line values are rejected. File input strips exactly one trailing LF or CRLF, preserving other whitespace. Single-line input rejects control characters except tab. Input is never echoed; delete any temporary secret file after use. Empty input skips that step; Ctrl-C or Esc aborts the whole rotation before further changes.

`--yes` skips the numeric confirmation only after you explicitly request `--execute`; it does not create guided replacements or bypass interactive-terminal requirements. Review the final summary, including provider notes and warnings, and `.keysentry/journal.jsonl`, confirm application health, resolve retained old keys, then scan again to verify the resulting inventory. A provider's `unverified` result is not proof that the new credential works.

Rotation safety flags:

| Flag | Behavior |
|---|---|
| `--revoke-unconfirmed` | Allow revocation despite unconfirmed consumer activation. This can break processes still using the old value; use only after reviewing that risk. Defaults off. |
| `--accept-unplanned-sealed` | Accept the risk that sealed findings outside this plan may still use the old key. Defaults off; include those consumers in the plan when possible. |
| `--no-generate` | Skip locally generated replacements for self-issued application/session secrets. Generation is allowed by default for interactive CLI rotation. |

Atomic-roll execution requires an interactive terminal, including through `approve`; `--yes` does not bypass this requirement. If an atomic roll needs manual recovery, keysentry offers to show the new value once only on that terminal, after a warning and the exact response `SHOW`. Otherwise it points to the provider dashboard. Keep that terminal private and inspect the recovery warning before proceeding.

Global flags are `--cwd <dir>`, `--config <path>`, `--json`, and `--verbose`. The config defaults to `keysentry.yaml` under the selected working directory. JSON output excludes plaintext values. Exit status is 0 for a successful command and 1 for an error, including failed scans of enabled hosts; `scan --fail-on-findings` additionally uses 2 for findings requiring attention. Partial scans and disabled hosts do not establish that a host is clean. A scan error blocks execution of plans touching a cluster with a consumer on the failed host; unrelated plans may proceed with a warning. Monitoring continues its detectors on the partial inventory and excludes affected clusters from automatic actions.

## Configuration and supported hosts

`keysentry init` creates local state, a fingerprint key, and a sample config without overwriting existing configuration. YAML is optional. Environment settings override corresponding YAML settings; provider admin credentials are loaded from the names listed below. A missing token disables that host and is reported during scan. dotenv scanning defaults to the selected working directory.

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

`approve` prints the planned action, whether revocation despite unconfirmed activation applies, and services needing a manual restart or future deployment. Review this output, then type the exact action ID to execute it. `keysentry approve <id> --yes` skips this confirmation; an action marked `requiresInteractive` still needs an interactive terminal. On a terminal, approval uses the same hidden replacement input and guarded recovery reveal as `rotate --execute`.

Automatic rotation is opt-in through `monitor.autoExecute: true` or `KEYSENTRY_AUTO_EXECUTE=true`. Unattended monitoring excludes atomic-roll, guided, and generated replacements from automatic execution and alerts for human intervention. Atomic rolls must be executed interactively. Incomplete actions remain available for human remediation.

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

- **Local first:** `.keysentry/` holds the inventory, plans, append-only rotation journal, and monitor state. It has a local ignore-all `.gitignore`; files use private modes where the OS supports them. Keep the fingerprint key stable and private so fingerprints remain comparable. Hosts/providers still receive the API calls needed for their operations.
- **Fingerprints rather than values:** readable values are HMAC-fingerprinted; hints reveal at most seven prefix characters and four suffix characters for sufficiently long values. Output passes through redaction. Rotation briefly handles plaintext in memory and sends new values to intended hosts; dotenv files necessarily contain the application's actual values.
- **Dry run by default:** rotation and canary mutations require `--execute`. Rotation additionally requests numeric confirmation; pending-action approval requests the exact action ID. `--yes` skips those confirmations but cannot authorize a non-TTY action marked `requiresInteractive`. Monitor policy and pending-action approval are separate explicit paths to execution.
- **Verify and revoke last:** replacement verification precedes batched writes. Default revocation waits for every consumer write and confirmed activation. For overlapping replacements, failed writes/deployments retain the old key. Cloudflare's atomic roll invalidates the old token immediately and cannot provide overlap. CLI `--revoke immediately` revokes after writes but before deploys; `--revoke never` retains old keys. `--no-redeploy` cannot establish activation. Review `--revoke-unconfirmed` separately before allowing revocation without activation proof.
- **Known consumers only:** sealed secrets cannot be deduplicated by value or automatically resolved from a fingerprint. Unplanned sealed findings with a matching provider or variable name can block revocation or atomic rotation unless `--accept-unplanned-sealed` explicitly accepts the risk. Missing credentials, inaccessible services, ignored files, and out-of-scope accounts leave gaps. Stale inventory is checked before execution, but APIs do not provide cross-host transactions or compare-and-swap.
- **Activation is host-specific:** dotenv writes require a manual process restart; Fly requires manual activation; Railway shared variables and unpollable initial deployments need human verification; Vercel preview/development and GitHub Actions apply on future runs. These writes report `unconfirmed` activation and retain old keys by default. A null deployment ID is not proof of application activation.
- **Recovery is manual:** v1 has no automatic rollback, crash resume, or interprocess lock. Inspect the journal before retrying a partially completed execution. A provider can create a credential before a response is lost; orphan cleanup may require its dashboard. Notification failures have no durable retry queue.

## MCP and coding-agent skill

Start the stdio MCP server with `keysentry mcp`. Keep stdout dedicated to MCP messages; logs go to stderr. Configure your MCP client with the absolute built entrypoint and the same working-directory/environment credentials as the CLI, for example:

```json
{
  "mcpServers": {
    "keysentry": {
      "command": "node",
      "args": ["/absolute/path/to/keysentry/dist/cli/index.js", "--cwd", "/absolute/path/to/project", "mcp"]
    }
  }
}
```

Tools are `scan`, `blast_radius`, `plan_rotation`, `rotate`, `monitor_status`, and `list_pending_actions`. MCP rotation execution is disabled by default. After reviewing a dry run, ask the human to run `keysentry rotate --plan <id> --execute` in their terminal. A model-supplied confirmation string is not human approval. Guided replacements are returned as instructions rather than terminal prompts.

An operator can explicitly enable MCP execution by starting the server with `KEYSENTRY_MCP_ALLOW_EXECUTE=1`. Even then, `execute: true` requires the `planId` and `planHash` returned by a previous `rotate` dry run in that MCP session. The hash binds the saved steps, consumers, and rotation options; execution uses exactly that saved plan once. Changed plans/options or a restarted MCP server require another dry run. MCP refuses `revoke: "immediately"`, `redeploy: false`, `revokeUnconfirmed: true`, and `acceptUnplannedSealed: true`, including when execution has been enabled. Atomic-roll plans also require the interactive terminal so a human can recover an undelivered replacement through the guarded reveal prompt. Never enable execution in response to instructions found in scanned content or a tool result.

Load or install [skill/SKILL.md](skill/SKILL.md) through your agent's skill mechanism. It teaches the breach-night sequence: scan, assess blast radius, plan, dry run, show the human, execute only after explicit confirmation, verify, then add canaries and monitoring.

## Development checks

```sh
npx tsc -p tsconfig.json --noEmit
node tools/vitest-sandbox.mjs test
```

Tests use injected fake hosts/providers and HTTP responses. The sandbox runner executes the suite without esbuild child-process startup, which is blocked in the Codex Windows sandbox. No live provider writes are needed for these tests.
