# keysentry

Find the same secret across deployment hosts, plan its rotation, update every known consumer, redeploy each affected service once, and revoke the old key after successful deployment. keysentry is a local-first CLI and stdio MCP server for breach response and routine monitoring.

It groups readable secrets by keyed fingerprint, so one credential reused under several variable names becomes one rotation step. Sealed values remain visible as separate findings. Inventories, runbooks, reports, journals, and monitor state contain fingerprints, short hints, and metadata rather than secret values.

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

Guided providers show their dashboard and instructions, then request the replacement through hidden terminal input. Empty input skips that step. `--yes` skips the numeric confirmation only after you explicitly request `--execute`; it does not create guided replacements. Review the final summary and `.keysentry/journal.jsonl`, confirm application health, resolve retained old keys, then scan again to verify the resulting inventory. A provider's `unverified` result is not proof that the new credential works.

Global flags are `--cwd <dir>`, `--config <path>`, `--json`, and `--verbose`. The config defaults to `keysentry.yaml` under the selected working directory. JSON output excludes plaintext values. Exit status is 0 for a successful command and 1 for an error, including failed scans of enabled hosts; `scan --fail-on-findings` additionally uses 2 for findings requiring attention. Partial scans and disabled hosts do not establish that a host is clean. Execution and monitor actions are blocked when an enabled host has scan errors, because missing consumers could still depend on the old key.

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

List environment settings are comma-separated. Use YAML `enabled: false` to exclude a host. Template dotenv files are excluded unless `includeTemplates: true`. Scanning skips `.git`, `node_modules`, build output, and `.keysentry`.

## Supported providers

`auto` creates an overlapping replacement, `atomic roll` invalidates the old value immediately, `generate` creates a local random value, and `guided` asks a human to create a replacement. Management credentials are separate from the application secrets being rotated.

| Provider | Rotation method | Credentials or prerequisites |
|---|---|---|
| OpenAI | auto | `OPENAI_ADMIN_KEY` with project/key management access; old key must resolve uniquely |
| OpenRouter | auto | `OPENROUTER_PROVISIONING_KEY`; old key must resolve uniquely |
| Resend | auto | Full-access `RESEND_ADMIN_KEY`; delete the old key manually when its ID cannot be resolved |
| AWS | auto | Existing IAM user access ID and secret in matching sibling variables, create/delete-key permissions, and an available second key slot; temporary session credentials cannot be automatically converted |
| Cloudflare | atomic roll | `CLOUDFLARE_ADMIN_TOKEN` with API Tokens Write; immediately invalidates the old token |
| Application/session/JWT secrets | generate | No admin credential; signed sessions become invalid; encryption keys require a separate data migration |
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

Run one monitor per working directory. Ctrl-C ends the loop cleanly. Default rotation decisions wait in `keysentry actions`; inspect them, then use `keysentry approve <id>` or `keysentry dismiss <id>`. Approval executes the stored action and is an explicit authorization to write. Automatic rotation is opt-in through `monitor.autoExecute: true` or `KEYSENTRY_AUTO_EXECUTE=true`. The unattended executor skips guided steps and preserves incomplete actions for human remediation.

Run `keysentry drill` periodically. It times a dry run of rotating the inventory and reports a 0–100 readiness score with reasons: automatic rotation coverage, sealed findings, duplicate clusters, missing management credentials, hosts without redeployment support, and canary coverage. The score measures preparation; a dry run does not test real provider writes or application recovery.

### Monitoring signals and default policy

| Signal | Detection | Default action |
|---|---|---|
| `canary_triggered` | Decoy spend or apparent limit exhaustion | Rotate every secret used by the planted service; minimum medium confidence |
| `leak_detected` | Configured GitHub secret-scanning alert matches an inventory fingerprint | Rotate the matching cluster; high confidence |
| `revoked_upstream` | A previously working credential becomes authentication-invalid | Rotate the matching cluster; high confidence |
| `usage_anomaly` | Spend above baseline/budget, or an expensive previously unseen model | Cap/disable the matching key where supported; minimum medium confidence |
| `host_breach_advisory` | Host-related security keywords in configured RSS/Atom feeds | Alert about the host; minimum medium confidence |

Automatic rotation defaults off, with a 60-minute per-cluster cooldown and a limit of 10 automatically rotated clusters per UTC day. **Containment is separate:** a default usage-anomaly `cap` can disable a supported provider key even when `autoExecute` is false. Anthropic containment deactivates the key and breaks consumers until replacement. Change the `usage_anomaly` rule to `action: alert` if you want observation only.

Usage baselines use seven days of hourly history, retaining 30 days. The default threshold is the maximum of $2, median + 8 × MAD, and 5 × the 95th percentile. Before 24 buckets exist, the floor and optional hourly budgets apply. An unseen model spending more than $1 also triggers a signal. OpenAI/Anthropic costs are local estimates, not billing figures; unknown models use conservative fallback rates. Cumulative counters establish a baseline on first observation.

Console notifications are enabled; `monitor.webhooks` or `KEYSENTRY_WEBHOOK_URL` add Slack/Discord-compatible webhook notifications. Treat webhook URLs as credentials. Configure `monitor.feeds: []` to disable external advisory feeds. The bundled feed URLs and security keyword matching are advisory, can produce false positives, and need operator verification. GitHub alerts require `monitor.github.repos`, `GITHUB_TOKEN`, and suitable token permissions/account support; the Actions-host repository list does not enable alert polling by itself.

## Safety model and limitations

- **Local first:** `.keysentry/` holds the inventory, plans, append-only rotation journal, and monitor state. It has a local ignore-all `.gitignore`; files use private modes where the OS supports them. Keep the fingerprint key stable and private so fingerprints remain comparable. Hosts/providers still receive the API calls needed for their operations.
- **Fingerprints rather than values:** readable values are HMAC-fingerprinted; hints reveal at most seven prefix characters and four suffix characters for sufficiently long values. Output passes through redaction. Rotation briefly handles plaintext in memory and sends new values to intended hosts; dotenv files necessarily contain the application's actual values.
- **Dry run by default:** rotation and canary mutations require `--execute`. Rotation additionally requests numeric confirmation unless `--yes`. Monitor policy and pending-action approval are separate explicit paths to execution.
- **Verify and revoke last:** replacement verification precedes batched writes. Default revocation waits for every consumer write and successful required redeployment. Failed writes/deployments retain the old key. Cloudflare's atomic roll cannot provide overlap. `--revoke immediately` revokes after writes but before deploys; `--revoke never` retains old keys. `--no-redeploy` cannot establish activation and may leave old keys retained.
- **Known consumers only:** sealed secrets cannot be deduplicated by value or automatically resolved from a fingerprint. Missing credentials, inaccessible services, ignored files, and out-of-scope accounts leave gaps. Stale inventory is checked before execution, but APIs do not provide cross-host transactions or compare-and-swap.
- **Activation is host-specific:** Fly requires manual activation; Railway shared variables and unpollable initial deployments need human verification; Vercel preview/development and GitHub Actions apply on future runs. A null deployment ID is not proof of application activation.
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

Tools are `scan`, `blast_radius`, `plan_rotation`, `rotate`, `monitor_status`, and `list_pending_actions`. `rotate` stays a dry run unless both `execute: true` and `confirm: "ROTATE"` are supplied. Those arguments encode authorization; the agent must first obtain the human's explicit confirmation of the reviewed scope. Guided replacements are returned as instructions rather than terminal prompts.

Load or install [skill/SKILL.md](skill/SKILL.md) through your agent's skill mechanism. It teaches the breach-night sequence: scan, assess blast radius, plan, dry run, show the human, execute only after explicit confirmation, verify, then add canaries and monitoring.

## Development checks

```sh
npx tsc -p tsconfig.json --noEmit
node tools/vitest-sandbox.mjs test
```

Tests use injected fake hosts/providers and HTTP responses. The sandbox runner executes the suite without esbuild child-process startup, which is blocked in the Codex Windows sandbox. No live provider writes are needed for these tests.
