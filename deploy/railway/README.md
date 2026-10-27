# Railway watcher deployment

Copy this entire folder so the Infrastructure as Code entry point remains at
`.railway/railway.ts`. Follow the shared [deployment steps](../README.md#railway)
for setup values, persistent state, and health checks.

1. Create an image service in a Railway project using the released
   `ghcr.io/grzenio22/keysentry` digest. Add a 1 GiB volume mounted at `/data`,
   prepare it as owner 65532 with mode 0700, and keep one replica.
2. Paste `KEYSENTRY_WATCHER_CONFIG`, `KEYSENTRY_WATCHER_KEY`,
   `KEYSENTRY_STATE_KEY`, `KEYSENTRY_VAULT_PASSPHRASE`, and
   `KEYSENTRY_WATCHER_VAULT` from local
   `keysentry watcher setup` into the service's Variables. Set
   `KEYSENTRY_STATE_DIR=/data`, `KEYSENTRY_VAULT=encrypted-file`, and
   `NODE_ENV=production`. Never generate a replacement state key in Railway.
3. With the Railway CLI installed separately, compare the SDK imports with
   `railway config init` for that CLI release, then run `railway config plan`
   and review it before `railway config apply`. The supplied facts verify the
   resource shapes and `preserve()` semantics but not the SDK's exact export
   names. This repository neither installs nor typechecks that SDK. Dashboard
   configuration is the fallback while that integration is checked.
4. Check the service logs for startup, state permission errors, and signed
   notification delivery. Enable a domain and configure `/healthz` in the
   platform only when the optional approval server and its public origin are
   configured. Outbound-only operation needs no domain.

## Publish your own dashboard template

1. First deploy and check a working project as above.
2. In Railway choose Workspace > Templates > New Template, or Generate Template
   from Project. Select the image service and persistent volume in the composer.
3. Mark all five setup values as user-supplied secrets. Keep their defaults empty.
   Do not use `${{secret(32)}}` for keys that must match local setup. Use
   `preserve()` in IaC to keep secrets already set in Railway.
4. Review the image digest, volume mount, one-replica setting, and variables,
   then publish the dashboard template. Share the generated Railway template
   URL. No universal one-click template ID exists in this repository.

Do not create `railway.json` or `railway.toml`: new services cannot opt into that
deprecated Config as Code, and existing files stop being read on 2026-12-01.
