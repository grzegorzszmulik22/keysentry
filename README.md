# keysentry

Find the same secret across deployment hosts, plan its rotation, update every known consumer, redeploy each affected service once, and revoke the old key after successful deployment. keysentry is a local CLI and dashboard for routine rotation and monitoring.

> **Status: keysentry 1.0 phase 3: local dashboard, token-free first run and everyday checks.** Adapters and native vault helpers are tested against fakes, not yet against live accounts or real credential stores. Try dry runs and a drill on a staging project before relying on provider writes. Real-browser passkey ceremonies, packed-package onboarding and deployed watcher operation still need integration checks. The cloud box is built and tested against a local emulator but not launched; team features are being built. Release signing keys are not published yet.

## Try it in 30 seconds

Run this in your project:

```sh
npx keysentry
```

The first-run scan needs no token, account, configuration or vault. It reads local environment/configuration files and bounded git history, then reports where it found keys, whether they appeared in commits, and possible deployment platforms inferred from project files. A key removed from today's files can still remain in git history and need rotation. Inferred deployment targets are suggestions, not verified live deployments.

The scanner makes no network calls. `npx` may contact the package registry to obtain the package itself. keysentry asks before creating `.keysentry/`; an interactive desktop terminal also offers to open the dashboard. To keep the scan entirely unsaved, use:

```sh
npx keysentry --no-save
```

`--no-save` writes nothing. History scanning has a time and commit budget; the summary says how much was scanned when history is incomplete. The scan skips binary/oversized content and common dependency/build directories, so it cannot establish that a project contains no secrets.

## Local dashboard

```sh
keysentry ui
keysentry ui --read-only
```

The dashboard brings together the key map, platform connection guidance, rotation preview, drill, autopilot, approvals, activity, notifications and settings. Connect shows the narrowest supported token and explains both its permissions and what keysentry will use it for. Values entered there go to the vault, not the project configuration.

Changes need a passkey with user verification and a fresh assertion bound to that exact action and input. Register passkeys only with `keysentry passkey register` at a human terminal; the dashboard cannot enroll them. An agent driving a browser could otherwise add its own virtual authenticator and authorize changes. The CLI and dashboard share the encrypted project `passkeys.json` store. Explicitly revealing a readable value also needs a passkey. Disarm remains available without one, including in read-only mode. Launches with a detected coding-agent marker are automatically read-only: no key changes. Previews and drills can still save encrypted plans, reports and readiness metadata.

The server binds only to `127.0.0.1` and opens as `http://localhost:<random port>` with a single-use sign-in link. `ui` writes that link into a private HTML launcher in the user directory and opens the file, keeping the token out of browser process arguments and normal terminal/JSON output. The file is deleted after two minutes. Open the printed file path if browser opening fails. `ui --print-url` prints the token-bearing URL only when explicitly requested at an interactive human terminal. All assets are bundled locally; Host/Origin checks, CSRF tokens and a strict content policy protect requests. It shuts down after 15 idle minutes. Normal responses contain metadata and hints, not values; reveal is explicit and clipboard copy attempts to clear after 30 seconds. Browser permissions or closing the tab can prevent clipboard clearing. These controls do not isolate credentials from other software running as your OS user.

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

The sandbox grants writes to the project's `.keysentry/` directory and the user data directory. `init` also receives the config file path; `plan -o`, `card --out` and `timeline --out` receive their exact output paths. Hook install/removal receives the resolved Git hooks directory, including `core.hooksPath`. First run, guard, dashboard and watcher commands can start Git child processes. Executing commands receive the configured dotenv consumer files from the inventory, plus their temporary-file prefixes for atomic replacement. If the inventory cannot be read yet, those commands receive the configured dotenv roots instead. Sandbox status comes from Node's permission API.

```sh
npm run build
node dist/cli/index.js --help
```

The examples below use `keysentry` for the package CLI. From this checkout, substitute `node dist/cli/index.js` or `npm run dev --` for `keysentry`. Package publication and packed-package verification remain release checks. This checkout is licensed under [Apache-2.0](LICENSE).

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

Review the dry run, then run `keysentry rotate --execute` yourself. It prints the diff and requests the number of secrets before proceeding. `--yes` skips that question, but CLI execution still requires an interactive human terminal and refuses known coding-agent environments. Use `--plan <id>` to execute a saved plan, or `--tier cloud,ai`, `--cluster <id>`, and `--host <id>` to narrow selection. Selecting a shared secret retains all known consumers, including those on other hosts.

Guided providers show their dashboard and instructions, then request the replacement through hidden input. Use bracketed paste for multi-line PEM or JSON values, or enter `@<path>` to read a value from a file. File input removes one trailing newline. Input is not echoed. Delete any temporary secret file after use. Empty input skips the step; Ctrl-C or Esc aborts the rotation before further changes.

Global flags are `--cwd <dir>`, `--config <path>`, `--json`, and `--verbose`; the default first-run action also accepts `--no-save`. Config defaults to `keysentry.yaml` in the selected directory. JSON output excludes plaintext values. Errors use exit status 1; `scan --fail-on-findings` uses 2 for findings requiring attention. A partial scan does not establish that a host is clear. Plans touching a host with scan errors are blocked; unrelated plans may proceed with a warning.

## Guard against committed keys

```sh
keysentry guard
keysentry guard --history
keysentry guard --staged
keysentry guard install-hook
keysentry guard uninstall-hook
```

Guard reports local findings; `--history` includes the bounded history scan, while `--staged` checks added staged lines and exits 1 when it would commit a detected secret. The optional pre-commit hook calls the installed `keysentry guard --staged`. It downloads nothing and prints a note if keysentry is unavailable. Hook installation/removal needs a human terminal, respects `core.hooksPath`, and preserves foreign hooks rather than silently replacing them.

Synthetic fixtures can be exempted with repository-relative `path:<glob>` entries in `.keysentry-allow` or its supported fingerprint format. Commit that file so the exceptions travel with the repository. Keep path exceptions narrow and never allow-list a real credential; the guard is a detection aid, not a proof that every possible secret was found. See [the guard format and limits](notes/guard.md#keysentry-allow).

## Key age, spending and weekly digest

```sh
keysentry hygiene
keysentry spend-limits
keysentry spend-limits --apply
keysentry digest
keysentry digest --send
```

Hygiene shows first-seen age, known copies and rotate-by dates, with a default 90-day rotation interval. First-seen means when keysentry observed a readable fingerprint, not when the provider created the key. Write-only keys cannot establish stable age. An unused-key hint appears when the provider's usage history covers 30 days. That coverage is not yet wired into the CLI/dashboard hygiene adapter, so these views currently omit the hint; absent evidence does not mean unused.

Set rotation intervals, provider spending caps and digest preferences in the dashboard Settings screen. `spend-limits` previews eligible changes; `--apply` requires human approval and write-role credentials. This phase supports OpenRouter per-key caps only, preserves a known tighter limit, and reports other providers as unavailable. A provider cap is not an aggregate account budget; missing usage/reference/cap data can leave a key without a proposal.

`digest` builds one calm summary of the recent period. `--send` sends it through configured notification channels after the human mutation check. A successful send means the channel accepted it, not that someone read it. A digest-day preference does not itself install a scheduler.

## Readiness card and incident timeline

```sh
keysentry card --out readiness.svg
keysentry card --out readiness.svg --share-platform --share-counts
keysentry timeline <planId-or-waveId>
keysentry timeline <planId-or-waveId> --out incident.md
```

The card is a self-contained SVG with the same readiness score as `keysentry drill`. By default it shares only the score and keysentry branding. `--share-platform` and `--share-counts` independently opt in to supported platform and completed-rotation statistics when available. It names an incident only when the completed rotation belongs to an autopilot wave with a recorded incident on that platform; routine rotations use ?rotated on <Platform>?. It contains no key values, hints, names or project names. The dashboard offers an image preview, SVG download and PNG clipboard copy where the browser supports it.

Timeline exports the selected plan or wave's recorded detection, decisions, writes, deployments, verification, grace and revocation events as Markdown. It cannot reconstruct events that were never recorded. Card and timeline exports are local files; review the metadata you choose to share before publishing them.

## Vault and credential roles

Tokens and keysentry's encryption/signing keys live in macOS Keychain, Windows current-user DPAPI, or Linux Secret Service. If an OS store is unavailable, keysentry asks before using a passphrase-protected encrypted file in `~/.keysentry/`. It remembers the backend in `~/.keysentry/vault-backend.json`, so returning to a desktop terminal does not switch key sets. If an older installation has an encrypted file and an available OS store without a remembered choice, it asks which to use; non-interactive runs use the file with a warning. A new file asks for the passphrase twice. Linux Secret Service needs `secret-tool` (usually the `libsecret-tools` package) and a session bus.

```sh
keysentry vault status
keysentry vault list
keysentry vault set GITHUB_TOKEN --role read
keysentry vault set GITHUB_TOKEN --role write
keysentry vault remove GITHUB_TOKEN --role read
```

`status` shows the backend, any weakness, and credential names by role. `list` shows names only. `set` never accepts a token argument; use its hidden prompt. With explicit `--stdin`, a human may pipe one value from their terminal while stdout remains a TTY. Without `--stdin`, both input and output must be TTYs. Known coding-agent environments are refused in either case. The default role is `write`. Use only the supported host and provider credential names listed in the tables below, plus `KEYSENTRY_PROXY_AUTH` for an authenticating proxy, the KMS credentials listed under [Bring your own KMS](#bring-your-own-kms-for-the-state-key), and `KEYSENTRY_OIDC_CLIENT_SECRET` for the team dashboard's single sign-on. `vault import-env` copies present host, provider and proxy credentials into the vault; they can then be removed from the environment. It never copies KMS credentials or the OIDC client secret, and the watcher keeps treating application variables with those names (for example an app's own `AWS_ACCESS_KEY_ID`) as keys to protect.

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

All HTTP uses the injected guarded client: HTTPS only, approved hostnames, bounded responses, and redirects checked against the same rules. Configured feeds and notification webhooks add explicit rules. Add a custom HTTPS service hostname, such as a Supabase custom domain, with `network.allowHosts` in [keysentry.example.yaml](keysentry.example.yaml). Entries must be exact DNS hostnames; wildcards and IP addresses are refused. Local HTTP endpoints remain blocked. Dotenv scanning makes no network requests. `network`, help and version output do not open the vault. Rules derived from a self-hosted server you configured may carry that URL's port and are shown as `host:port`.

## Corporate proxy, private CA and offline mode

```yaml
network:
  proxy: http://proxy.corp.example:3128   # or HTTPS_PROXY; credentials never go in this file
  noProxy: [vault.corp.example]            # plus NO_PROXY; exact hosts here, .suffix entries from NO_PROXY
  caFile: certs/corp-root.pem              # PEM certificates trusted in addition to Node's default roots
  offline: false                           # true: no breach feeds or security news
```

- **Proxy.** Every request goes through an HTTP CONNECT tunnel; TLS still runs end to end to the destination and verifies its name, so the proxy sees only host names. `network.proxy` wins over `HTTPS_PROXY`. Store proxy credentials with `keysentry vault set KEYSENTRY_PROXY_AUTH` (value `username:password`); they are sent only as `Proxy-Authorization` on the CONNECT request. Only Basic authentication is supported (no NTLM or Kerberos). An `http://` proxy carries that credential across your network unencrypted; doctor warns about it.
- **Private CA.** `network.caFile` adds certificates to Node's default roots, never replacing them. Those defaults are Node's bundled Mozilla list plus any certificates in `NODE_EXTRA_CA_CERTS`; the operating system's store counts only when Node runs with `--use-system-ca`. The file may hold only PEM certificates (and `#` comment lines); a private key or anything else rejects the whole file. Adding a CA widens trust for every host keysentry contacts, so add only your organization's root. keysentry's own connections keep checking certificates even when `NODE_TLS_REJECT_UNAUTHORIZED=0` is set, and doctor warns about that variable.
- **Fail closed.** A proxy, CA file or team policy setting that cannot be used refuses every request with a fixed message; keysentry never silently connects directly. `keysentry doctor` explains the problem, and `keysentry network` shows the current proxy, CA and offline state above the allowed hosts.
- **Deployed watcher.** `watcher setup` puts the certificates from `network.caFile` (the certificates, not the path) into the encrypted deployment vault, and with `network.proxy` also the proxy credential: `KEYSENTRY_PROXY_AUTH` from the vault, or the one in `HTTPS_PROXY` after you confirm. A file that cannot be read stops setup. The watcher uses `network.proxy` and `network.noProxy` as configured, so it must be able to reach that proxy; for a hosted platform outside your network, remove `network.proxy` before setup. `HTTPS_PROXY` from your terminal is not carried; set it in the watcher's environment if it needs one. A watcher whose proxy or CA settings cannot be used, or whose last three connection attempts to its proxy all failed (until one succeeds again), answers `/healthz` with HTTP 503 and a fixed reason, and `keysentry watcher status` reports it unhealthy.
- **Offline mode.** keysentry stops polling breach feeds and security news, and removes their hosts from the allowed list as a backstop. Autopilot waves start only from feed incidents, so they never start; alerts and automatic actions come only from your own signals (GitHub secret-scanning alerts, canaries, keys revoked upstream and usage anomalies). Provider and host APIs, notifications and health checks keep working, and you can still rotate any key yourself. `watcher setup` carries offline mode into the deployed watcher. `doctor`, `network`, `watch`, `monitor` and `watcher status` say when it is on.
- **Not proxied:** syslog audit export and the cloud box, which has its own egress. `keysentry box send-tokens` leaves `network.proxy` and `network.noProxy` out of the box's deployment (the box reaches provider APIs from Google's network and cannot reach your proxy) and says so; the certificates from `network.caFile` are kept. A team policy with `requireProxy` refuses to send tokens to a cloud box. Syslog cannot be tunnelled, so it refuses a host that HTTPS requests would send through the proxy (the same proxy and no-proxy decision); add the host to `noProxy` (exactly, or as `.suffix`) to allow a direct TLS connection. A team policy that requires the proxy refuses syslog export entirely.

## Verify and audit

```sh
keysentry verify --offline
keysentry verify
keysentry audit verify
```

The offline command compares the bundle with its adjacent local manifest. The online command additionally checks published signed checksums through the guarded client. A local manifest comparison checks consistency, not who published the files. Run verification from an independently obtained copy, such as a fresh `npm pack` of the published version: a modified bundle can lie about its own checks. Source checkouts are reported as development builds. Until signing keys are published, online verification prints: `Release signing keys are not published yet; only the local check ran.` A local bundle mismatch blocks `rotate --execute`; a missing manifest warns and requires typing `yes`, including with `--yes`.

`.keysentry/audit.jsonl` records metadata for scans, saved plans, approvals, vault changes, doctor runs, state resets and every rotation journal event. Every hash-chain record has an HMAC under a vault-held key, and checkpoints are signed; registered secrets are redacted. Forged appends require the vault MAC key. The saved vault head detects truncation behind the last checkpoint; an uncheckpointed suffix can still be removed. `audit verify` always consults the vault for this log path and returns exit status 1 for a failed MAC, a changed chain, or a nonempty log without an anchor. The audit log remains after a state reset.

Public markers under `~/.keysentry/audit-heads/` are hints only; removing one never skips the vault lookup. The environment vault cannot persist audit heads, so a later `audit verify` refuses a nonempty unanchored log. Its audit MAC key is process-local unless `KEYSENTRY_VAULT_AUDIT_MAC` supplies the same 32 UTF-8 bytes on every run. These backends provide no durable tail-truncation check across runs.

### Audit export

```yaml
audit:
  export:
    - { kind: syslog, id: siem, host: logs.corp.example, port: 6514 }        # RFC 5425 syslog over TLS
    - { kind: otlp, id: otel, url: https://otel.corp.example }               # OpenTelemetry logs (OTLP/HTTP JSON)
    - { kind: s3, id: archive, endpoint: https://s3.eu-west-1.amazonaws.com, bucket: audit-archive, region: eu-west-1 }
    - { kind: webhook, id: hook, url: https://hooks.corp.example/keysentry } # Standard Webhooks, Ed25519 signature
```

```sh
keysentry audit export --dry-run          # what would be sent; contacts nothing
keysentry audit export                    # send now
keysentry audit export status             # progress per target and every webhook signing key
keysentry audit export secret otel bearer # store a target credential (hidden input or --stdin)
```

Export sends only records whose hash chain verified, in order, and remembers per target how far it got: a crash can resend a batch, never skip one. Every entry's MAC is checked again on the exact bytes that are sent. Receivers should deduplicate on `(source, log, seq)`. The watcher exports after every cycle, beside its loop, so a slow target never delays the next cycle. Each HTTPS target gets its own network client that reaches only its host and follows no redirect, so an OTLP target may use any ordinary custom header name (`audit export secret <id> header` takes `Name: value`; transport headers such as `Host` or `Content-Type` are refused). S3 objects are named `<prefix><yyyy>/<mm>/<dd>/<source>/<log>/<first>-<last>.jsonl`, so two logs (for example a watcher whose state was recreated) never share an object. Syslog over TLS has no acknowledgement: when a server keeps the connection open after a batch, the run says delivery is unconfirmed.

Webhook signatures: this computer signs with its device key, and a deployed watcher or cloud box signs the batches it sends with its own watcher key. `keysentry audit export status` lists every one of those public keys (`whpk_…`, with key ids and who holds each); receivers should trust exactly those keys and pick one by the `keysentry-key-id` header. Run `status` again after `watcher setup` or a new cloud box, and update the receiver.

Records carry metadata only: no key values, tokens or URLs with credentials. Before 1.0, keysentry's syslog structured-data ID `keysentry@32473` uses the documentation enterprise number from RFC 5612; a registered IANA Private Enterprise Number must replace it. Details: [notes/audit-export.md](notes/audit-export.md).

### Bring your own KMS for the state key

```yaml
kms: { provider: vault-transit, address: https://vault.corp.example, keyName: keysentry }
# or: { provider: aws-kms, keyId: arn:aws:kms:eu-west-1:111122223333:key/…, region: eu-west-1 }
#     { provider: gcp-kms, keyName: projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k }
#     { provider: azure-key-vault, vaultUrl: https://name.vault.azure.net, keyName: keysentry }
```

```sh
keysentry kms status    # provider, key and a live unwrap check
keysentry kms migrate   # wrap the existing state key; type MIGRATE to confirm
keysentry kms rotate    # re-wrap under the key's current version
```

With a `kms` section, the project's state key is stored only wrapped by your key and is unwrapped into memory at start. A KMS that is unreachable, denies access, or holds a disabled or deleted key stops keysentry with a fixed message; it never creates a new state key in its place. Deleting or disabling the KMS key therefore makes saved state unreadable, by design. `watcher setup` then prints `KEYSENTRY_STATE_KEY_WRAPPED` instead of `KEYSENTRY_STATE_KEY`, and the watcher needs the KMS credentials in its secret settings. Store KMS credentials with `keysentry vault set` (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `GOOGLE_SERVICE_ACCOUNT_KEY` or `GOOGLE_OAUTH_ACCESS_TOKEN`, `AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`, `VAULT_TOKEN`); `--role read` is enough for unwrapping at start. Required key permissions: AWS `kms:Encrypt` and `kms:Decrypt`; Google `roles/cloudkms.cryptoKeyEncrypterDecrypter`; Azure `keys/get`, `keys/wrapKey`, `keys/unwrapKey` on an RSA key; Vault `read` on the transit key plus `update` on its encrypt and decrypt paths. KMS addresses must use port 443. Details: [notes/kms.md](notes/kms.md).

- Two processes that start a new project at the same time (for example `ui` and `watch`) create one wrapped state key between them: creation holds `.keysentry/state-key.lock`, and the second start uses the first one's key. A lock left by a keysentry process that stopped is not taken over automatically: the start says to remove that file once no keysentry command is running.
- Vault Transit: a Vault that answers with a warning that it ignored the binding parameter, or that decrypts with a different context during keysentry's one-time check, is refused.
- Azure Key Vault wraps with RSA, which is public-key encryption. keysentry checks the project binding after unwrapping, but anyone who has the key's public key and can write to your keysentry vault can build a wrapped key that passes that check, for a data key they chose; AWS KMS, Google Cloud KMS and Vault Transit need encrypt permission on your key for that. See [the threat model](docs/THREAT-MODEL.md).
- `kms rotate` rewraps this computer's copy only. A deployed watcher keeps its own `KEYSENTRY_STATE_KEY_WRAPPED` under the key version that was current at `watcher setup`: keep that version enabled, or run `watcher setup` again and redeploy before you disable it.

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
| Fly | `FLY_API_TOKEN` | `FLY_ORG` or `hosts.fly.apps` / `FLY_APPS` | Sealed values; stages updates and rolls Machines one at a time through the Machines API; stopped Machines stay stopped; an app with no Machines remains unconfirmed |
| GitHub Actions | `GITHUB_TOKEN` and configured repositories | `hosts.github.repos` / `GITHUB_REPOS` | Repository secrets are sealed; encrypted writes apply to the next workflow run |
| dotenv | None | `hosts.dotenv.roots` / `KEYSENTRY_DOTENV_ROOTS` | Local `.env` and `.env.*` files; no application restart |

List environment settings are comma-separated. Use YAML `enabled: false` to exclude a host. `FLY_API_TOKEN` without `FLY_ORG` or configured app names disables Fly with a scope message. Template dotenv files are excluded unless `includeTemplates: true`. Scanning skips `.git`, `node_modules`, build output, and `.keysentry`.

### More deploy platforms and secret stores

These hosts are opt-in: a host you have neither configured nor given a token is not listed in scans or doctor. Store each token with `keysentry vault set <NAME>`; a `--role read` copy is used for scans.

| Host | What keysentry reads and writes | How new values take effect | Token to create |
|---|---|---|---|
| Netlify (`hosts.netlify`) | Site and shared team variables per deploy context; secret values stay sealed except their `dev` value. Writes change only the selected context value. | Production: keysentry rebuilds the published commit and confirms it. Previews, branch deploys and shared variables: on their next deploy (unconfirmed). | `NETLIFY_TOKEN`: a personal access token with an expiry |
| Heroku (`hosts.heroku`) | App config vars; add-on owned vars are refused. | On write: every config var change creates a release; keysentry confirms that release and never starts another. `--no-redeploy` cannot hold it back. | `HEROKU_API_KEY`: an OAuth authorization with `read-protected,write-protected` |
| DigitalOcean App Platform (`hosts.digitalocean`) | App spec variables; SECRET values are encrypted and stay sealed. Writes send the spec back unchanged apart from the selected values, and are refused when a log destination or registry credential in the spec is not encrypted (`EV[…]`), since a full spec update could overwrite it. | On write: every spec update creates a deployment, which keysentry confirms. | `DIGITALOCEAN_TOKEN`: custom scopes `app:read` and `app:update` |
| Cloudflare Workers and Pages (`hosts.cloudflare`, needs `accountId`) | Worker plain-text bindings and secret names; Pages variables per environment. A Pages write is checked afterwards: every other variable and deployment setting (bindings, compatibility date) must be unchanged. | Workers: on write (each secret write deploys a new version, confirmed from the deployment list). Pages: on the next Pages deployment (unconfirmed). | `CLOUDFLARE_WORKERS_TOKEN`: an account API token with Workers Scripts and Cloudflare Pages permissions |
| Supabase Edge Functions (`hosts.supabase`) | Secret names only; values are never read. Writes add or replace the named secrets. | Immediate: functions read a new secret on their next invocation; no deploy. | `SUPABASE_FUNCTIONS_TOKEN`: a scoped personal access token with Edge Functions secrets read/write |
| Coolify (`hosts.coolify`, needs `baseUrl`) | Application and service variables (values need the `read:sensitive` permission). | Applications: keysentry restarts (or, with `redeploy: deploy`, deploys) and confirms the deployment. Services: restart only, unconfirmed. | `COOLIFY_TOKEN`: an API token with `read:sensitive`, `write` and `deploy` |
| Zeabur (`hosts.zeabur`) | Service variables per environment. Writes replace the set with only the selected values changed. | keysentry restarts the service, but Zeabur returns no deployment to confirm (unconfirmed). | `ZEABUR_TOKEN`: an API key |
| Kubernetes Secrets (`hosts.kubernetes`, needs `server` and `namespaces`) | Secrets in the namespaces you list. Secrets that something else writes are read but never written, because their owner would restore the old value: any Secret with an owner reference, Secrets of External Secrets, Sealed Secrets, the Vault Secrets Operator, cert-manager or the Secrets Store CSI driver, and TLS pairs (`kubernetes.io/tls`). keysentry still reads them, so a rotation sees every copy of a key: it never rolls a key held there (a roll would end it at once), and after replacing it elsewhere it keeps the old key and tells you to update it in the controller's source store, then revoke the old key yourself. Service account and bootstrap tokens and Helm release records are skipped. Conditional writes keep every other key. | Manual, unless `restartDeployments` names the Deployments that use a Secret: keysentry then rolls them like `kubectl rollout restart` and confirms. | `KUBERNETES_TOKEN`: a short-lived ServiceAccount token (`kubectl create token`) bound to a namespaced Role |
| AWS Secrets Manager (`hosts.awsSecretsManager`, needs `region`) | JSON secret keys, or one variable for a plain secret. A new version becomes current only if the secret did not change meanwhile; replacing existing JSON values keeps the secret's own formatting. | Manual by default; set `activation: immediate` when every consumer reads the secret at use time. | `AWS_SECRETS_MANAGER_ACCESS_KEY_ID` and `AWS_SECRETS_MANAGER_SECRET_ACCESS_KEY` (optional `AWS_SECRETS_MANAGER_SESSION_TOKEN`) for a dedicated IAM principal |
| HashiCorp Vault KV v2 (`hosts.vault`, needs `address`) | String keys under the configured paths. Writes patch only the selected keys with check-and-set. | Manual by default; `activation: immediate` when consumers read at use time (Vault Agent templates re-render on their own schedule, so leave those manual). | `VAULT_TOKEN`: a token with a read policy, plus `patch` for rotation |
| Doppler (`hosts.doppler`) | Raw secret values of root configs (branch configs only with `includeBranchConfigs`). Writes carry a current-value precondition and keep each secret's visibility (for example `restricted`) and value type. | Manual by default; `activation: immediate` only when every consumer fetches at use time. `doppler run` injects values at process start, and Doppler integrations sync on their own. | `DOPPLER_TOKEN`: a service token for the config |
| Infisical (`hosts.infisical`, needs `projects`) | Shared secrets per project, environment and folder. | Manual by default; `activation: immediate` when consumers read at use time (SDK caches and Infisical Agent refresh on their own schedule). | `INFISICAL_TOKEN`, or `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET` for a Universal Auth machine identity |

How a host applies new values decides when an old key may be retired. A host that keysentry can confirm (a confirmed deployment, an on-write release, or an immediate write) lets the old key be revoked after the grace period. An unconfirmed host keeps the old key until you accept its next deploy or finish the rotation yourself, exactly as for Fly, GitHub Actions and dotenv. Secret-store automation you configured (Doppler or Infisical integrations, AWS rotation functions, Kubernetes controllers such as Reloader, Vault Agent) may react to a change; keysentry neither starts nor waits for it.

The same applies to `keysentry undo`. On a host whose activation keysentry cannot confirm (Zeabur, Netlify previews, branch deploys and shared variables, Cloudflare Pages, Coolify services, Kubernetes Secrets without `restartDeployments`, secret stores left `manual`, and Fly, GitHub Actions and dotenv), undo writes the old values back but cannot see them go live, so it reports the activation as unconfirmed and keeps the replacement key. Restart or redeploy those services yourself, then delete the replacement key in the provider console.

Self-hosted servers (Coolify, the Kubernetes API server, Vault, a self-hosted Infisical) must be addressed by an https DNS name; IP addresses are refused everywhere. A URL may name a port (`https://coolify.example.com:8000`, `https://k8s.example.com:6443`, `https://vault.example.com:8200`); keysentry then allows exactly that host and port and nothing else. Use `network.caFile` for a private certificate authority. Environment scope overrides: `NETLIFY_ACCOUNT_SLUG`, `NETLIFY_SITE_IDS`, `HEROKU_APPS`, `HEROKU_TEAM`, `DIGITALOCEAN_APPS`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_WORKERS_SCRIPTS`, `CLOUDFLARE_PAGES_PROJECTS`, `SUPABASE_PROJECT_REFS`, `COOLIFY_URL`, `ZEABUR_OWNER_ID`, `ZEABUR_PROJECT_IDS`. The first-run scan (`npx keysentry`) also infers these platforms from `netlify.toml`, `.netlify/state.json`, `heroku.yml`, `app.json`, `Procfile`, `.do/app.yaml`, `wrangler.toml`/`.json`/`.jsonc`, `supabase/config.toml` and `zbpack.json` (`Procfile` is also read by other platforms, so treat it as a hint; `app.json` counts only beside `heroku.yml` or a `Procfile`, because Expo projects use the same file name).

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
| SendGrid | auto | `SENDGRID_ADMIN_KEY` (Full Access, or a restricted key with API Keys permissions) in the same account or subuser; the replacement gets the old key's exact scopes; the management key itself is never rotated |
| Twilio API keys | auto | A Main API key (`TWILIO_ADMIN_KEY_SID` + `TWILIO_ADMIN_KEY`) or the Account SID and Auth Token (`TWILIO_ADMIN_KEY_SID` = `AC…`, plus `TWILIO_ADMIN_ACCOUNT_SID` for a Main key); the secret and its `SK…` SID must sit side by side, under the same names, in every consumer. Before creating anything keysentry proves the pair: the secret must authenticate as that SID, and a SID that is the conventional partner of another secret in the service (`TWILIO_API_KEY` for `TWILIO_API_SECRET`) is never borrowed; otherwise the rotation is guided. Auth Tokens and Main keys stay guided |
| Google Cloud API keys (server-side) | auto | `GOOGLE_API_KEYS_ADMIN_KEY` (a service-account JSON key with API Keys Admin, whose `project_id` names the project) or a short-lived `GOOGLE_OAUTH_ACCESS_TOKEN` plus `GOOGLE_API_KEYS_PROJECT` (not a secret); API targets, IP restrictions, annotations and the bound service account are copied; deleted keys stay restorable for 30 days |
| Public Google API keys | guided | Firebase web config keys, Maps keys for browsers and apps, any Google key in a variable a build tool ships to clients (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `PUBLIC_`, `NUXT_PUBLIC_`, `NUXT_ENV_`, `GATSBY_`, `VUE_APP_`, `NG_APP_`, `STORYBOOK_`, `NX_PUBLIC_`, `REDWOOD_ENV_`, `PLASMO_PUBLIC_`, `SANITY_STUDIO_`, `WXT_`), and keys with browser, Android or iOS restrictions. Such a key is restricted, not secret, and lives in shipped web pages and app builds, so rotating it breaks installed clients: keysentry explains this, guides the replacement (tightening its restrictions is usually the right fix), never arms it, and never deletes the old key. Delete it yourself once the shipped clients have updated |
| Google service-account JSON keys | guided | Human Cloud Console administration; never armed for autopilot |
| Neon personal API keys | auto | `NEON_ADMIN_KEY` from the same user; delete the old key by hand (Neon shows no value hints); organization and project keys and connection strings stay guided |
| Upstash Redis and QStash | atomic roll | `UPSTASH_ADMIN_EMAIL` + `UPSTASH_ADMIN_KEY` (Developer API, Read/Write, native Upstash accounts). A reset invalidates every form of the credential at once (the password, the REST token, every Redis URL, possibly the read-only token), so every service holding any form loses access unless it is updated in the same run. Before a reset keysentry lists every current form from the management API and looks for each one across the whole inventory by fingerprint, whatever the variable is named or was classified as (a bare password under `CACHE_PASSWORD` counts). It resets only when the run updates every form it finds: plan those clusters together (`keysentry rotate --cluster <id> --cluster <id>`; other forms in the same service are updated with the reset). It refuses, naming the variable, when another place holds a form the plan does not update, and switches to a guided reset when an Upstash-like variable is sealed or unreadable, when any value in a service that holds a form is sealed or unreadable, when the forms cannot be listed, or when the last scan was incomplete. QStash tokens follow the same rule. A reset whose outcome is unknown is reported as possibly done, because the old credential may already be invalid |
| Mistral | guided | Human console access; an Enterprise `MISTRAL_ADMIN_KEY` lets keysentry identify and delete the old key |
| Groq, Replicate, Postmark, Clerk | guided | Human console access; keysentry verifies the key and guides the replacement (no key-management API) |
| Private keys | guided | Issuer/owner access and a certificate or trust-distribution procedure |
| Crypto wallets | guided | Move funds to a new wallet first; replacing a variable cannot protect already exposed funds |
| Unknown secrets | guided | Identify the issuer and every consumer before replacement |

Verification differs by provider. Some read endpoints accept restricted credentials but return limited access; some credential types have no safe verification endpoint. Provider permissions, endpoint behavior, and account scope must be checked for the target account. See module notes under [notes/](notes/) for API assumptions and gaps. The phase 6 adapters were built from vendor documentation without live accounts; [notes/providers-a.md](notes/providers-a.md) and [notes/providers-b.md](notes/providers-b.md) list what is unverified.

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

## Breach autopilot

Autopilot is an explicit authorization for selected keys, hosts and limits. Start in your normal terminal:

```sh
keysentry scan
keysentry drill
keysentry arm --hosts railway --grace 15 --max-services 10
keysentry autopilot status
```

`arm` lists eligible keys and explains exclusions. It requires a completed, passing drill from the last 24 hours. Use `--cluster <ids>` to narrow selection, `--valid-days <n>` to set the authorization lifetime, and `--health '<serviceKey>=https://app.example.com/health'` to add an application check. Defaults are 90 days, 15 minutes of grace and at most 10 services per wave. Non-secret defaults belong in the `autopilot` section of [keysentry.example.yaml](keysentry.example.yaml). The device key signs the plan, which is saved in encrypted state; re-arming replaces it and is audited.

For a write-only key, `arm` offers a supervised adoption rotation. The prompt says plainly that this rotates the key now. You can decline it; that key then remains outside automatic coverage. Adoption records the replacement's fingerprint and provider key reference, rather than retaining its plaintext. After watcher rotations, status can show **re-arm to refresh adopted keys**. `keysentry arm --refresh` reviews and signs updates in the same local CLI/`watch` state store. A separate deployed watcher's adoption updates are not automatically imported into that store. Reconcile its original encrypted state and matching keys before re-arming or renewing that deployment; remote update import and live-state migration remain unavailable.

**News alone never rotates.** One uncorroborated report alerts and requests approval. A trigger needs an official advisory describing credential exposure in the platform's own systems, or credential-exposure reports corroborated by an official source or a second independent news owner naming the same platform. Each watcher reads the sources itself. Its first successful read records a silent baseline; only later unseen items can become evidence. Dated items must be no more than 72 hours old and cannot be future-dated. An outage, denial, tutorial, phishing story or compromise of a third-party package or Action is not authorization to rotate your keys.

Autopilot will never automatically rotate payment keys, database credentials, data-encryption keys, wallet or private keys, atomic rolls such as Cloudflare, guided providers, or generated secrets outside the exact-name allow-list. Scope growth, changed values, an expired plan or an untrusted signature prevents automatic execution and requests approval. A new consumer is not silently added to the plan.

Each incident gets one rotation wave. Follow-up reports for the same host within the default 30-day cooldown request review instead of starting another automatic wave. Services deploy one at a time; configured health checks run after activation and again before deferred revocation. A fresh read-role scan checks current consumers before settling grace; an incomplete scan holds automatic rotation and revocation. The first verification, deployment or health-check failure stops the wave and keeps old keys valid when revocation has not begun. An interrupted settlement can leave some old keys already revoked; inspect its report. For next-deploy hosts, old keys stay valid unless the signed plan contains the required acceptance and maximum-deadline revocation consent. Phase 2 does not automatically detect an early next deployment.

## Run the watcher

```sh
keysentry watch                    # local vault and encrypted project state
keysentry watch --port 8787        # optional approval/health server
keysentry watch --once             # one scheduled cycle, including safe settlement
keysentry watcher setup
keysentry watcher status https://watcher.example.com
```

Run one watcher per state directory. Locally it uses the same vault and state as the CLI. `watch` and `watch --once` do not require a TTY, so they can run unattended with the required vault/state material. They still refuse detected coding-agent environments; automatic effects stay within signed armed-plan scope or a specific approval. `watcher setup` guides token selection using the actual platform capabilities, creates deployment and state keys, seals the configuration, and points to the chosen template under [deploy/](deploy/README.md). Setup exports only credentials needed by enabled hosts and the armed plan's providers, asks separately before exporting each environment-sourced credential, and lists the exported names. Hosted configurations exclude console notifications. Setup does not deploy anything. It warns when you would host the watcher on a platform it protects, because that platform also holds the watcher's own credentials.

Setup prints `KEYSENTRY_WATCHER_KEY`, `KEYSENTRY_STATE_KEY`, `KEYSENTRY_VAULT_PASSPHRASE`, the sealed `KEYSENTRY_WATCHER_CONFIG` and encrypted portable `KEYSENTRY_WATCHER_VAULT` once, only in an interactive terminal. Store all five values in your platform's secret settings only. The portable vault supplies the chosen host/provider credentials, scope and signing material absent from the fixed sealed-config format. Do not put these values in command arguments, a committed configuration, logs or a JSON export. `KEYSENTRY_WATCHER_CONFIG_FILE` can point to a file containing the sealed configuration. The image keeps its encrypted vault and state under `KEYSENTRY_STATE_DIR=/data`; keep their keys and passphrase outside that directory. Existing POSIX state directories must have mode 0700, and the volume must persist across runs.

Each `watcher setup` creates a new deployment key, state key, vault passphrase and portable-vault identity. It does not migrate an existing live volume. To renew a deployed watcher:

1. Use its original matching vault, keys and encrypted state to inspect and finish or undo every grace-pending or stopped rotation. Reconcile any adopted-key updates before creating the replacement authorization; remote updates are not imported automatically by the local CLI.
2. Disarm and stop the old watcher. Retain a secure backup of its unchanged encrypted volume and separately protected original keys for recovery and audit inspection.
3. Prepare the new setup and use a fresh private state directory or volume with all five newly generated secret settings. Keep the old volume unchanged; do not point the new state key or passphrase at it, and never store an unlock key alongside encrypted state.

The local dashboard does not provide automatic export/import of remote adopted-key updates or migration of a live watcher. Keep the original deployment material available until that reconciliation and all pending recovery work are complete.

The templates cover Docker Compose, Railway, Fly, Render and scheduled GitHub Actions. They still require the release image/digest and platform checks described in [deploy/README.md](deploy/README.md). Scheduled Actions can run late or be skipped; caches can be evicted, and public-repository caches must be treated as public encrypted data. An Actions watcher with missing state starts alert-only, including its first run. After checking its status, use `keysentry autopilot resume --relay` from your computer to authorize recovery on its next check. Resume releases the missing-state hold; it does not clear an explicit disarm or widen the signed plan. Authenticated sequence numbers detect rollback within a running process, but restoring an entire older cache across runs cannot be detected without a separately retained newer sequence. This mode cannot promise an exact response time or protection against complete cache rollback.

The watcher resumes interrupted work, polls the relay and feeds, handles incident waves and approvals, settles due grace, runs monitoring and sends a daily signed heartbeat. If no external notification channel has accepted a message within 24 hours, state is unwritable, the armed plan is invalid or clock skew exceeds five minutes, it enters alert-only mode. Console output does not satisfy this delivery check. Acceptance by a channel does not prove that a person read the message. Status shows the plan, waves and deadlines, delivery time and next settlement. An optional public approval server needs an HTTPS origin and correctly configured proxy/binding; `--port` alone does not provide TLS.

## Cloud box (not launched)

The cloud box is a hosted watcher that would run inside a Google Cloud Confidential Space VM. It is built and tested,
but it is **not launched**: there is no hosted box to sign up for, and nothing in this repository creates cloud
resources. You can run the whole flow on your own computer against a local emulator:

```sh
npm run dev -- box provision --emulator                 # from a source checkout; keeps running
keysentry box check local-box                           # in another terminal: verify before anything is sent
keysentry box send-tokens local-box                     # verify again, then seal this project's watcher deployment to the box
npm run dev -- box provision --emulator --mode unlock-on-restart
keysentry box unlock local-box                          # after a restart, in unlock-on-restart mode
keysentry box allowlist verify                          # the signed public log of allowed box images
```

`box check` prints every check by name: the attestation token's signature and issuer, both nonces (the box's key
and your fresh challenge), production debug status, supported hardware, `STABLE` support, memory monitoring off,
no environment or command override, the box's project and service account, and the image digest. In the emulator the
digest is checked against the emulator's own test digests, and the output says so. For the hosted box the allowed
digests will come from the signed public allow-list (`keysentry box allowlist verify` checks it today); that wiring
ships with the launch. `send-tokens` and `unlock` refuse with the failed check named and send nothing. The box receives the same
deployment `watcher setup` creates, sealed to its attested key, and runs the same watcher. In the emulator, the checks
use the emulator's test keys and digests, and the output says so.

The three ways the box keeps tokens at rest: *standard* (a Cloud KMS key released only to the allowed image in
keysentry's project and service account), *bring your own KMS* (the key and its release policy in your own project),
and *unlock on restart* (part of the key stays on your computer; after a restart the box pauses autopilot, sends one
notice, and waits for `keysentry box unlock`).

> Your keys are decrypted only inside a confidential machine running the exact open-source build you can verify. Our
> staff cannot log in to it and the cloud provider cannot read its memory. In the standard option we control the
> key-release policy; every change to it is public. With bring-your-own-KMS, only you control it.

What that claim still relies on (Google's attestation service and signing keys, the Confidential Space image, and
the TDX or SEV hardware) is in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md#cloud-box).

## Notifications

```sh
keysentry notify add telegram      # also discord, slack, ntfy, webhook, resend, smtp, console
keysentry notify list
keysentry notify test
keysentry notify verify ABCD-EFGH
keysentry notify verify --file signed-message.json
keysentry notify remove <channel-id>
```

Prompts hide tokens, passwords, webhook URLs and topics. Secret channel fields are stored in the vault as `notify/<channelId>/<field>`; YAML contains only channel IDs/kinds and non-secret settings such as an ntfy server or email addresses. `notify list` shows IDs and kinds only. Notification destinations are explicitly added to the guarded client's user rules; health URLs use the purpose **health check you configured**. Review actual contacts with `keysentry network`.

Watcher messages are signed by the device or configured watcher key and carry a short verification code. Verification checks the stored/full signed message with a locally trusted public key; the short code alone is not a signature or an approval. Generic webhooks carry the full signed JSON and signature headers. Messages contain no secret values; short key hints are opt-in with `autopilot.showHints`. Channel operators can still read notification metadata, suppress delivery or replay a message. Use an independent channel where possible, and run `notify test` after changing its settings.

## Approvals with a passkey

```sh
keysentry passkey register
keysentry passkey list
keysentry passkey remove <credential-id>
keysentry approve <action-id>
keysentry approve <action-id> --relay
```

Local registration serves a one-page app on a random port, binds to `127.0.0.1` and opens as `http://localhost:<port>` with a one-time token. Host and Origin checks, a strict content policy and bundled static script protect that local page. It closes after successful registration, five minutes or Ctrl-C. Local passkeys use RP ID `localhost`; the recorded origin must also match when approving.

A pending approval binds to the exact planned keys, consumers and steps. Requests normally expire after ten minutes; Actions-mode requests allow 60 minutes for scheduled checks. Approval is single-use. `approve <action-id>` executes a local autopilot action through the same scan, eligibility, deployment and revocation checks used by armed waves. `approve <action-id> --relay` verifies the watcher-signed request, shows the keys and available hints, asks for confirmation and publishes a device-signed approval. The watcher executes accepted grants on its next check; publication alone does not confirm execution. Guided changes still need the user. Existing monitor approvals remain available. The relay cannot authorize a different action or expand an armed plan. Public ntfy topics are readable and writable by others: a random topic reduces discovery, while trusted signatures provide authorization.

Passkeys are scoped to their relying party and origin. A localhost registration does not register a passkey for a public watcher. `passkey register --origin https://watcher.example.com` explains that registration must happen there. The current approval server has no `/register` page; the local dashboard never enrolls passkeys (the team dashboard enrolls a candidate from an admin's single-use link, see Teams and enterprise). Notifications include an approval-page link only when a passkey is registered for the watcher's public origin; otherwise they direct you to `keysentry approve <action-id>` on your computer. Passkey enrollment requires the local human CLI. Arming and channel changes require the local human CLI or a passkey-gated local dashboard action; watcher setup uses the human CLI. Relay approvals cannot widen policy.

## Kill switch

```sh
keysentry disarm
keysentry disarm --relay
```

Local disarm sets the saved off-state. With `--relay`, it also publishes a device-signed disarm bound to that watcher. A successful command confirms publication; the watcher applies it on its next check and polls again between automatic engine steps. Authenticated disarms have no age deadline, but transport can still delay or suppress them, so check the watcher's status. Disarming at a terminal or on the local dashboard needs no passkey; on the team dashboard it needs the member's own passkey (a sign-in session alone cannot turn autopilot off) and the team's channels are told who disarmed. Disarming never waits for a quorum. The approval server also has a Disarm page. Disarm stops new automatic effects and grace settlement; old keys that have not yet been revoked stay valid. It does not restore a key already revoked.

Set `KEYSENTRY_ALERT_ONLY=1` on the watcher to force alert-only operation. Re-arming requires the local human CLI or a passkey-gated local dashboard action and a new signed plan. When the watcher's own host has an incident, it still rotates or requests approval for the other covered keys and names operating credentials that need local rotation. It does not automatically replace its own operating credentials.

## Teams and enterprise

Team mode is part of the open core (Apache-2.0, no licence checks). A team shares one signed **roster** (who is on the
team, their roles, device keys and passkeys) and, optionally, one signed **policy file** (rules that only narrow what
keysentry may do). Both live beside your project: the roster in encrypted state, the policy as a JSON file you can
commit. Admins sign changes with their own computer's device key. For security reviews, `docs/CONTROLS.md` maps these
features to SOC 2 and ISO 27001 and names the evidence each one produces.

**Roles.**

| Role | Can |
|------|-----|
| viewer | read the team dashboard and approval requests |
| operator | also ask for and approve rotations, finishes, undos, spending limits and dismissals (each with their own passkey or device key), and disarm autopilot with their own passkey |
| admin | also sign roster and policy changes on their own computer, and ask for and approve arming, settings, notification channels, vault entries and reveals on the team dashboard |

Roles decide who may approve, what the team dashboard allows, and whose signatures count. Someone running keysentry on
their own computer with their own host tokens is still governed by the team policy there, but not by roles: the roster
cannot take tokens away from a person who holds them. The same holds for the team dashboard's host: anyone with a
terminal there can use the tokens in its vault, so protect that host like the tokens themselves.

**Joining a team.**

```sh
keysentry team init --id ana --name Ana --email ana@example.com    # this computer becomes admin 1; turns on team.enabled
keysentry team card -o ben.json                                    # on Ben's computer: public keys only
keysentry team add ben --role operator --card ben.json --email ben@example.com
keysentry team export -o roster.json                               # send roster.json to Ben, then on his computer:
keysentry team apply roster.json --fingerprint 3f9a-12c4-77d0-ab18-0c2e-9d41-5b7a-e630   # read it out by phone or chat
keysentry team list                                                # members, roles and the fingerprint
keysentry team verify                                              # roster, team mode and policy; exit 1 when changes are paused
```

A computer with no roster trusts the first one it applies only when you give it the fingerprint an admin read to you
(the first 128 bits of the roster's hash): signatures alone cannot protect a first use, because whoever writes a roster
also chooses its admin keys. After that, each new version must extend the one in use (rollback and fork protection)
and is checked against a copy of the applied version in your vault, so an older state file copied back is refused. An
environment-variable vault (CI) cannot keep that copy, so there the encrypted state file is the only record.

**Signing changes.** A roster change needs the signatures of as many admins of the version being replaced as the
roster's admin threshold, or as the applied policy's `approvals.wideningAdmins` when that is higher (adding or promoting
a member widens who can approve). When one signature is enough, `team add`, `remove`, `role`, `notify`, `sso`,
`add-passkey` and `threshold` sign and apply at once. Otherwise they write a proposal with your signature; other admins
review it and run `keysentry team sign <file>` on their own computers, and anyone applies it with `keysentry team apply
<file>` once it has enough signatures. A removed admin cannot sign the next version, a new admin cannot vote for their
own addition, lowering the threshold still needs the old number of signatures, and a change that would leave fewer
admins with device keys than the policy's `wideningAdmins` is refused (nothing could be signed after it). When one
admin's signature can add an operator while the policy needs more than one approver, `team add` and `team role` warn
that this admin could add a member whose key they hold and then meet the quorum alone.

**Keep a spare admin.** When every admin with a device key is needed to sign the next change, for example a team of
one admin, or the 2-of-2 `wideningAdmins: 2` with two admins in the policy example below, `team init`, the roster
commands and `policy sign` / `policy apply` warn "no spare admin". Losing one of those admin devices then means no
roster or policy change can ever be signed again: no member can be added or removed, no passkey added and no rule
changed. There is no bypass, by design: no reset command, recovery key or support channel can sign for a lost device,
because anything that could would also let an attacker take over the team. The only recovery is the spare itself: keep
at least one more admin with a device key than a change needs (three admins for `wideningAdmins: 2`), on a separate
computer, and add it before you need it. When an admin leaves or replaces a computer, add the replacement admin (`team
add <id> --role admin --card <file>`) while the old device can still sign, and only then remove the old one.

**Policy file.** Write a draft, sign it, apply it:

```json
{
  "approvals": { "required": 2, "requiredByTier": { "crypto": 3 }, "wideningAdmins": 2 },
  "autopilot": { "allowedHosts": ["railway", "vercel"], "allowedProviders": ["openai", "openrouter"], "maxServicesPerWave": 5,
    "allowMonitorAutomation": false },
  "network": { "offline": true, "allowHosts": ["hooks.example.com", "idp.example.com"], "requireProxy": true },
  "notify": { "allowedKinds": ["slack", "smtp"] },
  "rotation": { "revoke": "after-deploy", "minGraceSeconds": 900 },
  "audit": { "exportRequired": true }
}
```

```sh
keysentry policy sign team-policy.json     # fills in the team, version and link, then adds your signature
keysentry policy apply team-policy.json    # with enough admin signatures; sets team.policyFile in keysentry.yaml
keysentry policy show                      # the rules in plain English
```

Every rule only narrows: approvals need that many different operators or admins (the strictest tier of the keys
involved); autopilot arms only the listed hosts and providers, with at most that many services per wave and at least
that grace period; the monitor's automatic rotation and containment (`monitor.autoExecute`, `monitor.autoContain`,
their `KEYSENTRY_AUTO_*` overrides, and revoking unconfirmed keys on high-confidence signals) are turned off unless the
policy sets `autopilot.allowMonitorAutomation: true`, and even then they stay inside the listed hosts, providers and
`approvalTiers` (other keys wait for an approval); `network.offline` turns on offline mode; `network.allowHosts` drops
destinations you added (webhooks, health checks, feeds, the relay, ntfy and SMTP servers, audit export targets, single
sign-on hosts) that it does not list; `requireProxy` sends every request through your proxy and ignores no-proxy lists;
`notify.allowedKinds` drops other channels; `rotation` lowers revocation and raises grace, and with `minGraceSeconds`
neither `rotate --revoke immediately`, the "revoke now" answer at the grace prompt, nor `keysentry finish --now` (the
dashboard's early revoke) revokes an old key before it has been kept that long; `audit.exportRequired` pauses changes
until an audit export is configured.

The first policy needs the roster's admin threshold of signatures from current admins. A new version needs the
policy in force's `approvals.wideningAdmins` admins too, so a policy cannot relax its own rules with fewer signatures
than they require. After removing an admin who signed the policy in force, sign it again as a new version. While the
roster, the policy file or a policy requirement cannot be verified, keysentry pauses every change ("Changes are paused.
…"), including approvals, arming and watcher setup; disarming always works. Turning `team.enabled` off under an applied
roster also pauses changes: it never falls back to single-user mode. Arming at a terminal is signed by one admin's
device, so there a policy with `wideningAdmins` above 1 pauses arming; on the team dashboard the arm request collects
that many admins' approvals first.

**Approvals with a quorum.** When the policy needs two approvals, the first approval is recorded, not run:
`keysentry approve <id>` prints "Your approval was recorded: 1 of 2 team approvals so far… 1 more approval from a team
operator or admin who has not approved yet." and exits 0; the dashboard and the watcher's approval page show the count,
which includes only approvers who still qualify under the current roster. The action runs when a different member
approves. The same member or the same passkey cannot count twice, viewers and people outside the roster are refused,
and a member removed or demoted before the action runs stops counting. Monitor actions use the same quorum in team
mode. A request that recorded a quorum is never approved by a single approval because the roster stopped being
visible on that computer; approvals pause instead.

**Team dashboard changes run under the quorum.** On the team dashboard nothing changes because one member pressed a
button. A rotation, finish, undo, spending limit or dismissal (operators), or an arm, settings, notification channel,
vault or reveal change (admins), confirmed with the member's own passkey, becomes a team request bound to exactly that
change and counts as that member's approval; the dashboard answers "recorded: 1 of 2" and nothing runs yet. Other
members approve it on the Approvals screen with their own passkeys. Operator changes need `approvals.required`
operators or admins (by the risk tier of the keys involved); admin changes need `approvals.wideningAdmins` admins (the
roster's threshold without a policy). The change runs when the last approval arrives, as that member, after
keysentry checks the approvals again against the current roster and policy. Changes that carry a secret (storing a
token, adding a channel) and reveals are not kept with the request: after the approval, the member who asked makes the
same change again and it runs then; a revealed value only ever reaches that member's browser. Each approved request
runs once: it is claimed before it runs (under a lock other keysentry processes respect), so a retry, a second request or
another process never runs it again, even if the run was interrupted; make the change again to ask for new approvals.
Dismissing a pending request needs the approvals a change of the keys it concerns needs (a rotation of an AI-tier key
under `requiredByTier`, for example). Arming with adoption rotates the adopted write-only keys once inside the arm:
the arm request names them, covers exactly that rotation, and needs the approvals rotating them needs as well as the
arming admins. A reveal and a disarm are announced on the team's notification channels with the member's name.

**Team dashboard with single sign-on.** `keysentry ui --team --public-origin https://keysentry.example.com
--oidc-issuer https://idp.example.com --oidc-client-id keysentry` serves the dashboard behind your TLS proxy (keep the
`Host` header unchanged and rate-limit `/auth/*` and `/enroll/*` there). It refuses to start on a computer whose device
key belongs to a team admin: the dashboard faces the internet, and an admin key there would let anyone with a terminal
on that host sign roster and policy changes and approve as that admin. Run it on a computer that joined with `team
apply` and keep admin keys on admins' own computers. Register `https://keysentry.example.com/auth/callback` as the
redirect URI (scopes `openid email`) and store a confidential client's secret with `keysentry vault set
KEYSENTRY_OIDC_CLIENT_SECRET`, or use `--oidc-public-client`. Members sign in by verified email (ASCII addresses only,
compared without case) until an admin pins their identity provider identity: the dashboard's Account page shows the
issuer and subject, and

```sh
keysentry team sso ben --issuer https://idp.example.com --subject 00u1abcd2EFGH3ijk4l5
```

signs it into the roster. From then on only that exact issuer and subject sign in as Ben; a reassigned email address is
refused. Every change on the team dashboard needs the member's own passkey for the dashboard's host:

```sh
# On an admin's computer: a link signed with the admin's device key, valid 15 minutes, for one member and one address.
keysentry team invite ben --origin https://keysentry.example.com
# On the dashboard host, after Ben opened it (or download the card from the dashboard's Account page as an admin):
keysentry team passkeys pending -o passkeys.json
# Back on the admin's computer: compare the fingerprint with Ben, then sign the roster change; apply it on the host.
keysentry team add-passkey ben --card passkeys.json
```

The dashboard host never needs an admin's key: it checks the link's signature against the roster's current admins,
its expiry and its own address, and remembers each link once used (as a hash). The link is in the URL fragment, so
browsers never send it in a request line or log it; the page posts it. The passkey Ben creates there is only a
candidate: it grants nothing until the signed roster lists it, and it can only go on the card of the member whose link
created it. The authenticator model a candidate shows is reported by the authenticator itself and not verified.
Enrollment is rate-limited, exists only on the team dashboard, and is the only page that may create a credential; the
local dashboard never registers passkeys.

**What the identity provider can and cannot do.** It decides who can open the team dashboard and read it at their
role. It cannot approve, ask for changes, arm, disarm, change settings or reveal values: those need the member's own
passkey from the signed roster, and changes also need the team's quorum. It cannot add members, change roles or add
passkeys: those are roster changes signed by admins' device keys. A compromised provider can therefore read what a
member can read, but not change keys or turn autopilot off.

**Notifications per member.** `keysentry team notify ben --channels ops --min-severity urgent` sends a channel that
members are assigned to only messages at or above the lowest severity among them; channels assigned to nobody receive
everything. A channel that a member received stays member-owned when nobody receives it any more: the roster lists it
as retired and no computer sends it team messages, so a removed member's own chat never becomes a team-wide channel.
`team remove` and `team notify --clear` refuse while the member has channels no other member receives, unless
`--drop-channels` also removes them from `keysentry.yaml` on that computer. The watcher applies the routing and the
policy's channel kinds.

**Who did it.** Every audit event a team dashboard request causes records the signed-in member (`memberId`), and audit
exports carry it as the record's `actor`. Sign-ins, approvals and quorum progress name members too.

**Watchers.** `keysentry watcher setup` seals the verified roster and policy into the watcher's config, so a deployed
watcher counts members' roster passkeys and device keys toward the quorum, accepts disarms from operators' device keys,
routes notifications, and stops acting on an armed plan that falls outside the policy. A deployed watcher or cloud box
keeps the roster and policy it was set up with: a member you remove can still approve and disarm there until you run
`keysentry watcher setup` again (and `keysentry box send-tokens` for a cloud box). `team remove` and `team role` remind
you when a watcher or box is known.

## Safety model and limitations

- **Local first:** `.keysentry/` holds encrypted inventory, plans, rotation journal and monitor state, plus the metadata-only audit log and network receipt. It has an ignore-all `.gitignore`; files use private modes where the OS supports them. Encryption and fingerprint keys live in the vault. Hosts/providers still receive the API calls needed for their operations.
- **Fingerprints rather than values:** readable values are HMAC-fingerprinted; hints reveal at most seven prefix characters and four suffix characters for sufficiently long values. Output passes through redaction. Rotation briefly handles plaintext in memory and sends new values to intended hosts; dotenv files necessarily contain the application's actual values.
- **Dry run by default:** rotation and canary mutations require `--execute`. Rotation requests numeric confirmation; pending-action approval requests the exact action ID. `--yes` skips those questions but preserves the human-terminal and agent checks. Monitor policy and pending-action approval are separate explicit paths to execution.
- **Verify and revoke last:** replacement verification precedes batched writes. Default revocation waits for every consumer write and confirmed activation. For overlapping replacements, failed writes/deployments retain the old key. Cloudflare's atomic roll invalidates the old token immediately and cannot provide overlap. CLI `--revoke immediately` revokes after writes but before deploys; `--revoke never` retains old keys. `--no-redeploy` cannot establish activation. Review `--revoke-unconfirmed` separately before allowing revocation without activation proof.
- **Known consumers only:** sealed secrets cannot be deduplicated by value or automatically resolved from a fingerprint. Unplanned sealed findings with a matching provider or variable name can block revocation or atomic rotation unless `--accept-unplanned-sealed` explicitly accepts the risk. Missing credentials, inaccessible services, ignored files, and out-of-scope accounts leave gaps. Stale inventory is checked before execution, but APIs do not provide cross-host transactions or compare-and-swap.
- **Activation is host-specific:** dotenv writes require a manual process restart; unsupported Fly layouts need manual activation; Railway shared variables and unpollable initial deployments need human verification; Vercel preview/development and GitHub Actions apply on future runs. These writes report `unconfirmed` activation and retain old keys by default. A null deployment ID is not proof of application activation.
- **Recovery has limits:** encrypted in-flight values and the journal support resume and grace-period undo. A provider can create a credential before keysentry records its value; cleanup may require its dashboard. Undo may be unavailable for unreadable old values. Run one rotation/monitor/watcher process per project; this is not an interprocess execution lock. Watcher acknowledgments survive restarts, but channel delivery itself is not guaranteed.

## Development checks

```sh
npx tsc -p tsconfig.json --noEmit
npx tsc -p tsconfig.client.json
node scripts/build-ui.mjs --check
node tools/vitest-sandbox.mjs test
```

Tests use injected fake vaults, hosts/providers and HTTP responses. The sandbox runner executes the suite without esbuild child-process startup. No real keychain, provider account or network request is needed for these tests. Release builds and real OS-store checks are separate integration work; see [SECURITY.md](SECURITY.md) and [docs/ACCESS.md](docs/ACCESS.md).

When `KEYSENTRY_STATE_DIR` is set for a watcher/container, user metadata defaults to `<state dir>/user`. Set `KEYSENTRY_USER_DIR` to use another writable directory. Directory preparation errors name the affected path and the variable to set.
