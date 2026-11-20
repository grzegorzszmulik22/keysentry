# keysentry

When a platform you deploy on is breached, keysentry finds every copy of each secret across your hosts and rotates them
in a safe order: create the new key, update every known consumer, redeploy each service once, verify, then revoke the
old key. It is a local TypeScript CLI with a loopback dashboard; no account or hosted service is involved.

> **Status: pre-release.** Not yet published to npm. Host and provider adapters are built from vendor documentation and
> tested against fakes, not against live accounts. There has been no external security audit. Use dry runs and
> `keysentry drill` on a staging project before trusting provider writes.

## Quick start

Requires Node.js 22.13 or newer.

```sh
git clone https://github.com/grzegorzszmulik22/keysentry.git
cd keysentry
npm ci
npm run build
node dist/cli/index.js --cwd /path/to/your/project --no-save
```

The first-run scan needs no token, account, configuration or network access. It reads local env/config files and a
bounded slice of git history, then lists the keys it found (as fingerprints and short hints, never values), where they
appeared, and which deployment platforms the project files suggest. `--no-save` writes nothing.

Once published, the same scan will be `npx keysentry`. Below, `keysentry` stands for `node dist/cli/index.js`.

## Features

- **Inventory:** finds the same secret across dotenv files and deployment hosts by keyed HMAC fingerprint.
- **Rotation plans:** orders the work so each service redeploys once; dry run by default, `--execute` to apply.
- **Verify, then revoke:** the old key is revoked only after every consumer has the new one and redeploys succeeded.
- **Resume and undo:** an encrypted journal survives crashes; `resume`, `undo` and `finish` recover partial runs.
- **Guard:** `keysentry guard --staged` and an optional pre-commit hook block commits that add secrets.
- **Monitoring and autopilot:** breach feeds, GitHub secret-scanning alerts, canaries and usage anomalies; a signed,
  scoped plan can rotate automatically after a corroborated incident. News alone never triggers a rotation.
- **Dashboard:** `keysentry ui` serves a local page on `127.0.0.1`; changes need a passkey bound to the exact action.
- **Doctor and network receipt:** `doctor` explains what each token could do; `network` lists every host contacted.

## How it works

1. `scan` reads each configured host with read-only credentials and fingerprints every readable value.
2. `plan` groups copies of the same secret into clusters and orders the steps per service.
3. `rotate` shows a dry run; `rotate --execute` creates and verifies the replacement with the provider.
4. Consumers are updated and each affected service is redeployed once, with activation confirmed where the host allows.
5. The old key is revoked last (or kept, if any write or deploy failed), and every step goes to a tamper-evident log.

## Supported platforms

**Hosts and secret stores:** local dotenv files, Railway, Vercel, Render, Fly.io, GitHub Actions, Netlify, Heroku,
DigitalOcean App Platform, Cloudflare Workers and Pages, Supabase Edge Functions, Coolify, Zeabur, Kubernetes Secrets,
AWS Secrets Manager, HashiCorp Vault KV v2, Doppler, Infisical.

**Providers, automatic rotation:** OpenAI, OpenRouter, Resend, AWS IAM access keys, SendGrid, Twilio API keys, Google
Cloud API keys (server-side), Neon personal API keys, and self-issued app/session/JWT secrets (generated locally).

**Providers, atomic roll** (the old credential stops working immediately): Cloudflare API tokens, Upstash Redis and
QStash.

**Guided** (keysentry shows the steps and takes the new value through hidden input): Anthropic, Stripe, GitHub tokens,
Supabase, Slack, Mistral, Groq, Replicate, Postmark, Clerk, database credentials, private keys and unknown secrets.

The [user guide](docs/GUIDE.md) and [access guide](docs/ACCESS.md) list the exact token each integration needs and what
is still unverified.

## Safety model

- **First scan needs no tokens** and makes no network calls.
- **Dry run by default.** Every host or provider write needs `--execute` and a numeric confirmation at an interactive
  terminal. Commands that change keys refuse to run when a known AI coding-agent environment is detected.
- **No plaintext at rest.** Tokens live in the OS keychain (macOS Keychain, Windows DPAPI, Linux Secret Service) or a
  passphrase-protected file; inventory, plans and journal are encrypted. Output is redacted.
- **Guarded network access.** All HTTP goes through one client: HTTPS only, an explicit host allow-list, and redirects
  checked against the same rules. No telemetry.
- **Known limits.** keysentry only rotates consumers it can see; sealed values cannot be matched by content, and other
  software running as your OS user can still reach the vault. See [SECURITY.md](SECURITY.md) and the
  [threat model](docs/THREAT-MODEL.md).

## Documentation

- [User guide](docs/GUIDE.md): every command, configuration and limitation
- [Access guide](docs/ACCESS.md): tokens and permissions per integration
- [Architecture](docs/ARCHITECTURE.md) and [threat model](docs/THREAT-MODEL.md)
- [Self-hosted watcher deployment](deploy/README.md)
- [Example configuration](keysentry.example.yaml)

## Development

```sh
npm ci
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm test            # vitest: unit, integration and e2e tests
npm run build       # compile to dist/
npm run bundle      # single-file dist/keysentry.mjs
```

Tests use fake vaults, fake hosts and providers, and recorded HTTP responses: no keychain, account or network is needed.
`node tools/vitest-sandbox.mjs test/` runs the same suite in-process, which is what CI uses. The repository also holds
an optional cloud "box" and its control plane (`packages/control-plane`, `infra/terraform`); both are built and tested
against a local emulator and are not deployed.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for bundled third-party licenses.
