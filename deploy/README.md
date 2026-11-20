# Run your watcher

The container runs one watcher as user 65532. It has no shell and starts
`keysentry watch`. Keep one active watcher per state directory; replicas must not
share the same state. Platform costs and registry access depend on your account.
The templates have been checked locally as text and YAML, not deployed.

## Prepare on your own computer

1. Install a reviewed keysentry release, test your notification channel, select the
   keys to arm, and run the setup wizard in your own terminal:

   ```sh
   keysentry notify test
   keysentry watcher setup
   ```

   Setup supplies the sealed configuration and matching keys. Use the narrowest
   platform tokens shown by setup. If the watcher runs on a platform it protects,
   an incident there requires you to rotate the watcher's own tokens by hand and
   run setup again.

2. Store these five values in your platform's secret settings. Never put them in a
   Docker build argument, Dockerfile, repository variable, image, workflow YAML,
   or a committed file. Keep a separate secure backup.

   | Secret | Value from setup | Purpose |
   | --- | --- | --- |
   | `KEYSENTRY_WATCHER_CONFIG` | Entire sealed string beginning `ksw1.` | Supplies the sealed plan, notification and watcher settings |
   | `KEYSENTRY_WATCHER_KEY` | Matching base64 32-byte deployment key | Opens the sealed watcher configuration |
   | `KEYSENTRY_STATE_KEY` | Matching base64 32-byte state key | Encrypts recovery state; do not generate a replacement on the platform |
   | `KEYSENTRY_VAULT_PASSPHRASE` | Passphrase for the encrypted-file vault | Opens the watcher's encrypted vault |
   | `KEYSENTRY_WATCHER_VAULT` | Base64 encrypted portable vault | Initializes credentials, signing keys and runtime settings when the persisted vault is absent |

   Provider/platform credentials belong inside the encrypted vault initialized by
   setup. The watcher imports `KEYSENTRY_WATCHER_VAULT` only when its persisted
   vault is absent; an existing updated vault takes precedence. Preserve and
   restore encrypted state/vault following setup's instructions. Keep deploy-time
   keys outside the state directory. The deployment key opens configuration; it
   does not replace the separate state key.

   An alternative is to mount a file containing only the sealed string and set
   `KEYSENTRY_WATCHER_CONFIG_FILE` to its path instead of
   `KEYSENTRY_WATCHER_CONFIG`. Do not mount an unsealed JSON configuration.

3. Select the released image. Until the first image release, templates use
   `ghcr.io/grzegorzszmulik22/keysentry:1.0.0` and include a digest replacement comment.
   Replace it with the published immutable reference before deployment:

   ```text
   ghcr.io/grzegorzszmulik22/keysentry@sha256:<release-digest>
   ```

   Do not deploy the literal placeholder. Private GHCR images need your own
   registry credentials; public images do not. Build publication happens only for
   public repositories. The two Docker base images are already pinned by digest.
   The image workflow attaches buildx provenance and SBOM attestations. Images
   are currently unsigned; cosign keyless signing is planned for the publishing
   release, with OIDC permission added alongside the signing step.

4. Provision persistent state at `/data` with owner `65532:65532` and mode `0700`.
   The image prepares that mount point, but a provider volume may replace its
   permissions. If it does, initialize ownership and mode through the provider's
   volume-maintenance facility before starting the non-root watcher. The watcher
   refuses POSIX state directories with any group/other permission bits. It does
   not silently change existing permissions. State and the vault are encrypted;
   deploy-time keys stay outside the volume.

## Docker Compose

1. Copy `deploy/compose/docker-compose.yml` into a private working folder. From the
   repository root, for example:

   ```sh
   mkdir -p "$HOME/keysentry-watcher"
   cp deploy/compose/docker-compose.yml "$HOME/keysentry-watcher/"
   cd "$HOME/keysentry-watcher"
   umask 077
   touch .env
   chmod 600 .env
   "${EDITOR:-vi}" .env
   ```

   Fill `.env` with the five exact `NAME=value` assignments from setup. This is a
   local deployment secret file: do not commit or share it. Compose reads it with
   `env_file`. Replace the image reference with the released digest.

2. Create the container and named volume without starting the watcher:

   ```sh
   docker compose create watcher
   ```

   Docker normally copies the image's private `/data` directory permissions to a
   new named volume. Restore setup's encrypted state/vault into that volume before
   the first start when setup requires it. For an existing volume with incorrect
   permissions, first stop the watcher, find its volume, then initialize it with
   the same reviewed image, without passing any secrets:

   ```sh
   docker compose stop watcher
   watcher_container=$(docker compose ps -aq watcher)
   watcher_volume=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$watcher_container")
   watcher_image=$(docker inspect --format '{{.Config.Image}}' "$watcher_container")
   test -n "$watcher_volume"
   docker run --rm --user 0:0 --entrypoint /nodejs/bin/node \
     --mount "type=volume,source=$watcher_volume,target=/data" "$watcher_image" \
     -e 'const fs=require("node:fs"); fs.chownSync("/data",65532,65532); fs.chmodSync("/data",0o700)'
   ```

   This one-time initialization runs as root to prepare the volume. The watcher
   itself continues to run as 65532 with all capabilities dropped.

3. Start it and inspect logs for configuration or state-permission messages:

   ```sh
   docker compose up -d watcher
   docker compose logs --tail 100 -f watcher
   ```

   The root filesystem is read-only, `/tmp` is temporary, and `/data` persists.
   The default template exposes no ports. When you explicitly enable the approval
   server, configure `watch --port 8080`, publish that port only to your HTTPS
   reverse proxy, set the matching public origin during setup, and check
   `https://YOUR-WATCHER/healthz`. Otherwise use logs and signed heartbeats.

## Railway

1. Copy the entire `deploy/railway` folder, including its hidden `.railway` folder,
   to your deployment workspace. Create a Railway project and an image-based
   service using the released image digest. Add a 1 GiB volume at `/data` and keep
   a single replica.
2. Set the five secrets above in service Variables. Set these ordinary variables:

   ```text
   KEYSENTRY_STATE_DIR=/data
   KEYSENTRY_VAULT=encrypted-file
   NODE_ENV=production
   ```

   Prepare the volume permissions and restore setup's encrypted state if needed.
3. For IaC, use your separately installed Railway CLI in the copied folder:

   ```sh
   railway config plan
   railway config apply
   ```

   Review the plan before applying. The SDK import names in the template were not
   verified by the supplied platform facts; compare them with output from
   `railway config init` for your installed CLI before using IaC. Dashboard setup
   is the available fallback. No Railway SDK is a keysentry dependency.
4. Deploy, then inspect the service's Deployments/Logs view. This is an outbound
   worker with no domain by default. If you enable the approval server on the
   service's chosen port, add a public HTTPS domain, update the sealed public
   origin through setup, and configure Railway's health-check path as `/healthz`.

`railway.json` and `railway.toml` Config as Code are deprecated and stop being
read on 2026-12-01. Dashboard template publishing steps are in
[railway/README.md](railway/README.md).

## Render

1. Copy `deploy/render/render.yaml` into a repository you control as `render.yaml`,
   replace its image reference with the released digest, then create a Blueprint
   from that repository in Render. It creates a paid background worker with one
   disk mounted at `/data`; it has no inbound HTTP endpoint.
2. When prompted, paste all five setup secrets. Each uses `sync: false`;
   `KEYSENTRY_STATE_KEY` must be the setup value, not a Render-generated value.
   Later Blueprint syncs do not update these secrets: change them in the worker's
   Environment settings when setup is repeated.
3. Initialize the disk as owner 65532, mode 0700 through a provider maintenance
   operation if its initial mount permissions differ, and restore setup's
   encrypted state. Start the worker and inspect its Logs view for errors and
   daily signed heartbeats. A disk prevents scaling this service past one instance
   and changes deployment availability; keep one worker.
4. For browser approvals, create a web-service deployment deliberately instead
   of this worker template, run `watch --port 8080`, configure its HTTPS public
   origin through setup, and set Render's health-check path to `/healthz`. The
   worker template itself cannot provide an external HTTP health check.

## Fly.io

1. Copy `deploy/fly/fly.toml` to a private folder. Change `app` to a unique name,
   choose a nearby region, and replace the image with its released digest. Create
   the app and volume in that region:

   ```sh
   fly apps create YOUR-UNIQUE-APP
   fly volumes create keysentry_data --app YOUR-UNIQUE-APP --region ams --size 1
   ```

2. In a private mode-0600 local file such as `.watcher-secrets.env`, put the five
   exact `NAME=value` assignments from setup. Import through stdin, so values are
   not command-line arguments:

   ```sh
   fly secrets import --app YOUR-UNIQUE-APP < .watcher-secrets.env
   ```

   Use Fly's maintenance process to give the mounted volume owner 65532 and mode
   0700, and restore setup's encrypted state. Keep the secret file out of git.
3. Deploy one machine and inspect its logs:

   ```sh
   fly deploy --app YOUR-UNIQUE-APP --config fly.toml --ha=false
   fly logs --app YOUR-UNIQUE-APP
   ```

   No `services` or `http_service` section exists in the worker template. The
   machine remains running to poll sources. If you enable approval HTTP, set its
   port and HTTPS public origin through setup, then add Fly's HTTP service and an
   HTTP check with path `/healthz`; do not expose an unconfigured approval server.

## GitHub Actions

1. Copy `deploy/github-actions/keysentry-watch.yml` to
   `.github/workflows/keysentry-watch.yml` in a repository you control, on its
   default branch. Review the pinned actions: each is pinned to a full commit SHA
   (actions/cache v6.1.0 verified 2026-10-27).
2. Add the five setup values under Settings > Secrets and variables > Actions >
   Repository secrets. Add the ordinary repository variable
   `KEYSENTRY_RELEASE_TAG`, for example `v1.0.0`, selecting a release you reviewed.
   This workflow downloads the bundle and manifest from that release, then checks
   both against `SHA256SUMS` before running `node keysentry.mjs watch --once`.
   A checksum matches downloaded bytes; it does not independently authenticate
   the release publisher. Use the release verification process for publisher
   trust.
3. If setup produced encrypted recovery state, initialize it through a controlled
   first run, following setup's instructions. The workflow restores
   the latest `keysentry-state-` cache prefix and saves a new immutable cache as
   `keysentry-state-${{ github.run_id }}`. It serializes runs and saves recovery
   state even if a watcher tick fails. Cache only encrypted state; never put the
   deployment key, state key, passphrase, or a plaintext secret file in `.keysentry`.
   A cache miss, including the first run, starts alert-only and stays paused until
   a registered device sends a fresh signed `keysentry autopilot resume --relay`
   through the configured relay. Review the watcher's state before resuming.
4. Enable Actions and choose Run workflow to test it. Inspect the run's watcher
   logs and signed notifications. Exit 0 means the run completed, 1 means an
   error, and 2 means alert-only. Actions mode has no inbound approval server;
   use the outbound relay configured in setup.

Schedules run every ten minutes in UTC, but may be delayed or dropped during
load. They run only from the default branch. Public-repository schedules turn
off after 60 days without repository activity; forks start with schedules off.
Caches may be evicted after seven days without access or because the repository
cache limit is exceeded, and default-branch caches can be restored by pull-request
workflows. Keep backups and verify recovery before relying on unattended rotation.
The monotonic sequence is protected inside encrypted state. It detects an older
restore only after the same process has seen a newer sequence. Across separate
Actions runs, an older snapshot is detectable only when a newer snapshot is also
present; restoring an old snapshot alone does not provide an independent latest
sequence. Cache access also exposes encrypted vault files and plaintext audit and
network-receipt metadata to workflows that can restore the cache.
Reruns reuse the original run ID; an immutable cache with that ID cannot be
overwritten, so use a new workflow dispatch for a new recovery snapshot.

## Health checks

The distroless image has no shell, so it defines no Docker `HEALTHCHECK` command.
With the optional approval server enabled, use the platform's HTTP check against
`/healthz` over your configured HTTPS endpoint. For outbound-only workers, use
platform process status, logs, and the signed daily heartbeat. An HTTP 200 alone
does not prove that a notification was delivered or that automatic rotation is
enabled. The watcher falls back to alert-only after 24 hours without a successful
notification, when state is not writable, when authorization is invalid, or when
available HTTP Date evidence indicates more than five minutes of clock skew.

## What the watcher can reach

Every HTTP request uses keysentry's egress-checked client and appears in its
network receipt. A listed destination is permission to contact it when the
configured feature needs it; the watcher does not send to every listed host on
every tick. Review `keysentry network` and your chosen source list.

- Platform APIs: `backboard.railway.com`, `api.vercel.com`, `api.render.com`,
  `api.machines.dev`, `api.fly.io`, `api.github.com`.
- Provider APIs: `api.openai.com`, `api.anthropic.com`, `openrouter.ai`,
  `api.resend.com`, `api.cloudflare.com`, `iam.amazonaws.com`, `sts.amazonaws.com`,
  `api.supabase.com`, `*.supabase.co`, `api.stripe.com`, `api.sendgrid.com`,
  `slack.com`. Eligibility rules still restrict what may rotate automatically.
- Official sources: `blog.railway.com`, `railway.com`, `vercel.com`,
  `www.vercel-status.com`, `render.com`, `status.render.com`, `fly.io`,
  `status.flyio.net`, `community.fly.io`, `github.blog`, `www.githubstatus.com`.
- Security news: `www.bleepingcomputer.com`, `therecord.media`,
  `www.securityweek.com`, `www.theregister.com`, `api.theregister.com`,
  `krebsonsecurity.com`, `www.darkreading.com`, `arstechnica.com`,
  `feeds.feedburner.com`, `www.cisa.gov`, `www.helpnetsecurity.com`.
- Configured notifications/relay: `api.telegram.org`, `discord.com`,
  `hooks.slack.com`, `ntfy.sh`, `api.resend.com`, and exact custom webhook/ntfy
  hosts you explicitly configure. SMTP uses your configured mail host on TLS
  port 465 or STARTTLS port 587 and records it as `smtp:<host>`.
- Release checks: `github.com`, `objects.githubusercontent.com`,
  `release-assets.githubusercontent.com`. Actions additionally reaches GitHub's
  runner/action download, release, and cache infrastructure outside the watcher
  process; pulling the container image reaches GHCR.
- Exact custom source and HTTPS health-check hosts you explicitly configure.

## How to switch it off

To prevent new automatic work, set `KEYSENTRY_ALERT_ONLY=1` in the watcher's
environment and restart it, or use the approval page's Disarm control when
enabled. Disarming needs no passkey. `keysentry disarm` applies to the state used
by that CLI; on a separate local computer it must reach the watcher's state or
its configured control channel to affect the running watcher. Re-arming requires
the local CLI and a registered device.

To stop the process entirely, use your platform's Stop/Suspend control,
`docker compose stop watcher`, or `fly scale count 0 --app YOUR-UNIQUE-APP`.
For Actions, disable the workflow in the Actions menu. Preserve the encrypted
volume/cache and its separate keys while work is interrupted: deleting recovery
state can prevent a safe resume or finish. Stop/alert-only does not undo a prior
rotation. Review pending grace periods and finish them through keysentry.
