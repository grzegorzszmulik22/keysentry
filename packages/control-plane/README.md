# keysentry control plane — built, not deployed

Private Apache-2.0 package for the cloud-box control plane, its web page, its Cloud Run entry and image, and its
local emulator. Nothing in this package has been deployed, and no test calls Google, Stripe or any other external
service. Node >=22.13 is required. The package declares no dependencies of its own; the shared repository modules it
imports (WebAuthn, box handshake schemas, attestation verifier, egress guard, security primitives) bring the root's
dependencies with them, for example zod through `src/box/handshake`. It never imports the watcher, the CLI or the box
agent (checked for the image, see "Image").

## What is built, and what still needs a real account

Built and tested locally (fakes, happy-dom and the loopback emulator):

- The Cloud Run entry (`src/main.ts`, logic in `src/entry.ts`): non-secret settings from the environment, the two
  Stripe credentials read from Secret Manager through the metadata-server token, egress-guarded clients, one JSON log
  line per event (event and status), graceful shutdown on SIGTERM.
- The image `Dockerfile.control-plane` (repository root): one bundled file on distroless Node, non-root, no shell.
- A web page at `/`: create an account or sign in with a passkey, see the plan and boxes, start Stripe Checkout,
  create a box with the device public key from `keysentry box card`, sign out.
- `POST /billing/checkout`: a Stripe Checkout Session in subscription mode for the configured price, with
  `client_reference_id` set to the account.
- Passkey accounts with durable sessions (stored by hash), discoverable-credential sign-in, per-account session caps
  and bounded challenges.
- Stripe webhooks that grant the paid plan only for a paid subscription to the configured price, confirmed through
  the Stripe API, and revoke it on failed payments and subscription status changes.
- `POST /boxes` gated by the paid plan, a per-account box quota and a name reservation before any Compute call; in the
  hosted service it creates the instance only with `KEYSENTRY_CONTROL_PLANE_LIVE=1`. A name in flight cannot be
  reserved twice, and a Compute call with no definite outcome keeps the name held until reconciliation
  (`instances.get`) confirms the instance or frees the name.
- Downgrade: when an account stops paying, its boxes lose relay access, the page shows them as suspended and the
  control plane asks Compute to stop them (`instances.stop`). Paying again restores access, and the page starts a
  stopped box (`instances.start`). Nothing is deleted.
- The relay (short-lived message queues only, no blob storage), box authentication by Confidential Space attestation
  token, rate limits, and storage in memory, in a private directory or in a Cloud Storage bucket.
- Terraform (`infra/terraform/control-plane`) that runs exactly this entry with exactly these settings and grants
  exactly what it uses.

Not verified, because it needs real accounts: Stripe (Checkout Session creation, the restricted key's permissions,
webhook delivery), Cloud Run (startup, `X-Forwarded-For`, SIGTERM timing), Secret Manager reads, Cloud Storage under
load, Compute instance creation, reads, stops and starts with the custom role, and the Confidential Space tokens of a
real box. See [Deploy steps](#deploy-steps-written-not-run) below.

Known limits: one instance only (per-box and per-account work is serialized in process and Cloud Storage writes have no
compare-and-swap, so Terraform pins `max_instance_count = 1`; a revision rollout can briefly run two, and the other
instance may then keep a box's relay access for up to 30 seconds after a downgrade). No cancel or billing-portal link
on the page yet (customers cancel through Stripe's emails or support). No route to delete a box; a box is stopped only
when its plan ends. Passkeys are bound to the origin's host name, so choose the final domain before anyone signs up.

## Local validation

Run from the repository root:

```powershell
node tools/vitest-sandbox.mjs packages/control-plane/test
npx tsc -p packages/control-plane/tsconfig.json --noEmit
npx tsc -p packages/control-plane/tsconfig.ui.json --noEmit
node tools/vitest-sandbox.mjs test/infra/terraform.test.ts
node packages/control-plane/scripts/build-ui.mjs --check
node packages/control-plane/scripts/build.mjs --out dist-control-plane/control-plane.mjs
```

The root TypeScript project and ordinary root Vitest configuration do not include this package. CI must include the
package test path and both typechecks explicitly.

## Web page

`ui/` holds the page: `index.html`, `app.css` (the dashboard's tokens and tone from `docs/design/dashboard.md`),
`app.ts` (type-checked with `tsconfig.ui.json` against the DOM library) and `icon.svg`.
`scripts/build-ui.mjs` transpiles and embeds them in `src/ui-assets.ts`, which is committed; a test fails when it is
out of date. The server sends every file with the same security headers and a strict CSP:
`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self';
frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'`. There is no
inline script, style or event handler, and the script builds the page with DOM nodes and `textContent` only.

- Sign-up: `POST /auth/register/challenge` returns `userId` (the new account id's bytes, base64url); the page creates a
  discoverable passkey (`residentKey: required`, `userVerification: required`, `attestation: none`, Ed25519, ES256 or
  RS256) and finishes with `POST /auth/register/finish`.
- Sign-in: `POST /auth/login/challenge` with `{}` returns a challenge with no credential list; the browser offers the
  user's keysentry passkeys and `POST /auth/login/finish` (without `accountId`) finds the account by credential id.
- Checkout: `POST /billing/checkout`, then the browser goes to the returned `https://checkout.stripe.com/...` URL (the
  page refuses any other host). Stripe returns to `/?checkout=done` or `/?checkout=cancelled`; the plan changes only
  when the verified webhook arrives.
- Create a box: name plus the device public key `keysentry box card` prints (Ed25519 SPKI DER, base64), checked on the
  page and again on the server. A 202 is announced as "being checked".
- Boxes: each box shows its state (being created, created, suspended, stopped) with a short explanation; a suspended
  box says the paid plan ended, it was stopped, nothing was deleted, and how to resume. A stopped box on a paid account
  has a "Start box" button (`POST /boxes/:boxId/start`).

## Storage

`Storage` is `get`, `put`, `delete`, `list(prefix)` over JSON records with keys of at most 150 characters
(`[A-Za-z0-9_-]` segments joined by `/`).

- `createMemoryStorage()`.
- `createFileStorage(directory)`: one private directory, lower-case base32 file names, exclusive temporary files,
  fsync and atomic rename, symlinks refused, reads sized to the file. Windows deployments must supply the directory ACLs.
- `createGcsStorage({ http, bucket, accessToken, objectPrefix? })`: one object per key over the Cloud Storage JSON API
  through the injected `HttpClient`, bounded retries with backoff on 429 and 5xx, fixed error text.
  `metadataAccessToken(http)` reads the service account's token from the metadata server and caches it.

Account ids are lower-case hex, so an object name in a Cloud Storage URL can never look like a provider key to the
egress guard (which refuses such URLs).

## Relay

`createRelayStore({ storage, now?, ...limits })` exposes `publish`, `poll` and `sweep`: short-lived message queues
only. There is no blob storage: nothing in keysentry used it, and its shared quota let a few tenants refuse every other
box's disarms. Work is serialized per box, so one box never delays another. Each box has an index record
(`relay-index/<box>`: queue size and count), so the global quota never reads queues; global usage is rebuilt from index
records once per process. `sweep()` visits a bounded batch of boxes per call (64 by default) and the server runs it
every minute.

Accepted messages:

- The five handshake messages, validated with the shared strict schemas, signed lifetime exactly ten minutes.
- Approvals exactly as `publishApproval` sends them: `{"type":"keysentry-approval","v":1,"approval":{"actionId",
  "keyId","digest","at","sig"}}`, relayed only while `at` is within the verifier's ten-minute window.
- Disarms exactly as `publishDisarm` sends them: `{"type":"keysentry-disarm","v":2,"watcherId","keyId","at","sig"}`.
  `at` takes the same two forms as `validAt`. The relay does not bind `watcherId` to the box id (the CLI signs with
  the project id); the watcher checks its own id and the signature.

The relay validates shape, encoding, size and expiry only; endpoints verify signatures, attestation and authority.

Default limits: message 1 MiB; queue 128 messages and 2 MiB per box; 64 MiB for every box's queues together (507 when
full); ten-minute delivery TTL. The last quarter of the global quota (`reserveBytes`, 16 MiB) is kept for boxes within
their share (`shareBytes`, 256 KiB): once usage reaches it, a message that would take its box's queue above the share
is refused with 507, so boxes that fill their queues are stopped before they can refuse a disarm or a handshake for any
other box. To use up the reserve, a tenant would need 64 boxes (a paid account each, at the default quota) kept just
under their share.

## Accounts

`createAccounts({ storage, origin, ... })` reuses `verifyRegistration` and `verifyAssertion` with user verification
and one-use challenges, and refuses counter regression and cross-account credential reuse.

- Sessions are stored as `sessions/<sha256(id)>` (the id itself is never stored), with a 30-minute sliding idle expiry
  (written at most once a minute) and a 12-hour absolute lifetime. A sign-in beyond 8 sessions evicts that account's
  oldest. A restart or scale-to-zero keeps everyone signed in.
- The cookie is `__Host-ks_control_session` over HTTPS (`Path=/; HttpOnly; SameSite=Strict; Secure`); loopback HTTP
  uses `ks_control_session` without `Secure`.
- Challenges stay in memory: 2-minute TTL, at most 16 pending per client address and 20,000 in total (oldest evicted).
  `assertionChallenge(undefined)` starts a discoverable-credential sign-in.
- Registration writes the account, credential index, session and session index, and deletes all of them if any write
  fails, so a refused registration never burns the passkey.
- `overview(accountId)` returns `{ accountId, plan, boxes: [{ name, state }], boxQuota }` for `GET /account`, never
  billing identifiers.
- `reserveBox(accountId, name, deviceKey)` (402 unpaid, 403 at quota, 409 for any name already held, with `pending`
  set when it is this account's reservation still in flight or awaiting reconciliation) writes a pending ownership
  record with a reservation id and the enrollment key, and a `box-reconcile/<name>` index entry. `confirmBox` makes it
  active and is idempotent; `releaseBox` rolls a pending one back (only after a definite refusal); `holdBox` keeps it
  pending after a Compute call with no definite outcome. `pendingBox` offers a pending reservation that no request in
  this process is provisioning to reconciliation, and `settleBox(name, reservation, 'present' | 'absent' | 'foreign')`
  applies Compute's answer to that same reservation only. The quota (default 1) counts pending and active boxes.
  `ownsBox` and `boxOwner` see active boxes only.
- Downgrade: `boxAccess(name)` is `allowed` while the box's account is paid, `suspended` when it is not and `none`
  without an active owner; it is cached for `boxAccessCacheMs` (30 seconds), and this process's own writes drop the
  cache at once. `setPlan` from paid to free queues a stop for each active box (`box-stops/<name>`, written before the
  plan), and from free to paid drops stops not yet sent. `stopDue`, `markStopped`, `startTarget` and `markStarted`
  serve the server's stop and start steps. `overview` shows each box as `pending`, `active`, `suspended` (no paid plan)
  or `stopped` (stopped while unpaid, plan paid again). No box record is deleted.

## Billing

`createBilling({ storage, accounts, endpointSecret, priceId, stripe: { http, apiKey } })`.

`checkout({ accountId, origin })` posts to `https://api.stripe.com/v1/checkout/sessions` (form-encoded):
`mode=subscription`, `line_items[0][price]` = the configured price, `line_items[0][quantity]=1`,
`client_reference_id` = the account, `metadata[accountId]` and `subscription_data[metadata][accountId]`,
`success_url` = `<origin>/?checkout=done`, `cancel_url` = `<origin>/?checkout=cancelled`, and `customer` when the
account already has one. A paid account is refused (409) before Stripe is called. The reply must be a session in
subscription mode for the same `client_reference_id` with a `https://checkout.stripe.com/` URL. Stripe errors become
fixed text: 429, 5xx and network failures are 503 "Billing is temporarily unavailable."; anything else is 502
"Checkout could not be started."

`handle(rawBody, signature)` verifies the raw bytes (HMAC-SHA256, any `v1`, one `t`, ±300 s) and keeps a durable
event-id replay record, written only after the event was handled.

| Event | Effect |
|---|---|
| `checkout.session.completed`, `checkout.session.async_payment_succeeded` | Paid only for `mode: subscription`, `status: complete`, `payment_status` `paid` or `no_payment_required`, an existing account (`client_reference_id` or `metadata.accountId`), and a subscription that `GET /v1/subscriptions/{id}` reports `active` or `trialing`, for the same customer, with the configured price. If Stripe cannot be reached the webhook answers 503 and Stripe retries. |
| `checkout.session.async_payment_failed` | Free, when that checkout's subscription is the account's current one. |
| `customer.subscription.updated` | For the account's current subscription: `unpaid`, `canceled`, `incomplete_expired`, `paused` or another price revoke; `active` and `trialing` with the configured price grant; `past_due` keeps the plan while Stripe retries; `incomplete` changes nothing. An event older than one already applied is ignored; a grant needs the event's `created` time. |
| `customer.subscription.deleted` | Free, for the account's current subscription. |

The paid plan gates creating boxes and keeps them running: when it ends, the account's boxes are suspended and stopped
(see Accounts and HTTP server). `apiKey` should be a restricted key with Checkout Sessions write and Subscriptions read
only.

## HTTP server

`createControlPlaneServer({ origin, accounts, billing, relay, provisioner?, boxAttestation?, trustedProxy?, ... })`
returns `listen`, `close({ deadlineMs? })`, `issueBoxToken(boxId)` and `revokeBoxToken(boxId)`. The public Host must
equal the origin (DNS rebinding is refused). Pass `accounts: origin => createAccounts(...)` for a random-port origin.

| Method | Route | Access |
|---|---|---|
| GET | `/`, `/?checkout=done`, `/?checkout=cancelled`, `/app/app.js`, `/app/app.css`, `/app/icon.svg` | Public page files |
| GET | `/health` (hosted), `/healthz` (loopback) | Public |
| POST | `/auth/register/challenge`, `/auth/register/finish`, `/auth/login/challenge`, `/auth/login/finish` | Same-origin passkey ceremonies |
| GET, DELETE | `/session` | Session; delete also requires Origin and CSRF |
| GET | `/account` | Session |
| POST | `/billing/checkout` | Session, Origin and CSRF; body `{}` |
| POST | `/billing/webhook` | Stripe signature over the raw bytes |
| POST | `/boxes` | Owner session, Origin and CSRF; body `{ "name", "deviceKey" }` |
| POST | `/boxes/:boxId/start` | Owner session, Origin and CSRF; body `{}`; the paid plan and this account's active box |
| GET, POST | `/boxes/:boxId/messages` | Owner session, or that box's attestation token or issued bearer while its account is paid |

Cloud Run reserves some paths that end in `z`, so the hosted health path is `/health`.

`POST /boxes`: `name` must be a Compute instance name (`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`, not `gcp-`) and
`deviceKey` the owner's enrollment device public key (Ed25519 SPKI DER, base64, 44 bytes); otherwise 400. A pending
reservation of that name that nothing in this process is provisioning is reconciled first (below). Then the plan,
quota and name are checked and the name reserved (402, 403, 409; a name in flight is refused without a Compute call)
before the provisioner is called. Compute accepts: 201. A definite refusal (no instance was created: nothing was sent,
or a 4xx other than 408 and 409): the reservation is released and the answer is 502. Any other outcome (409
alreadyExists, 408, 5xx, a timeout or transport error, an unreadable reply): the name stays held and counted against
the quota, and the answer is 202 `{ "boxId", "state": "pending" }`. Without a provisioner it answers 503 "Creating
boxes is not available yet."

Reconciliation (on the next request for the name, and in the minute sweep for every `box-reconcile/` entry) asks
Compute for the instance (`instances.get`). An instance with this box id and the reservation's enrollment key confirms
the box; an instance that is not this reservation's releases the name (it is never adopted); no instance releases the
name once the reservation is `reconcileSettleMs` old (two minutes), so an insert Compute accepted moments ago is not
taken for a refusal; no answer keeps it pending.

Downgrade: a box credential (attestation token or bearer) for a box whose account has no paid plan is refused with
403 "This box is suspended: its account has no paid plan." on every request, so a cached attestation cannot outlive
the suspension. The minute sweep, and every handled webhook, request a stop (`instances.stop`) for each queued box
still unpaid; a failed request is retried. `POST /boxes/:boxId/start` asks Compute to start the box (`instances.start`)
once the plan is paid again (402 unpaid, 403 not this account's active box, 502 when Compute refuses, 503 without a
provisioner). `server.maintain()` runs the sweep's box work on demand.

Box access: a hosted box presents a Confidential Space token for this server's origin (`relayCredential` in
`src/box/agent/main.ts`), checked by the shared verifier against `boxAttestation`'s JWKS (or the pinned PKI root),
issuer, audience, time (at most an hour old), secure boot, `dbgstat`, `swname`, `STABLE`, hardware, memory monitoring
off, no overrides, project, service account and allowed digest. `submods.gce.instance_name` must name the box in the
route, and the box must exist. Issued 43-character bearers remain for the emulator and tests.

Headers on every response: the CSP above, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`Cache-Control: no-store`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy:
same-origin`, `Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)`, and HSTS
over HTTPS.

Rate limits (token buckets, least recently used evicted beyond 10,000): per box credential (120 a minute), per signed-in
account (120), per client address for anonymous requests, page files and failed credentials (120), and
`/billing/webhook` per client address (300). The client address is the socket peer, or with `trustedProxy: { header,
hops }` the entry `hops` from the right of that header (2 behind an external Application Load Balancer). Connections: at
most 1,024, and 64 per socket address without a trusted proxy. Bodies are JSON only. Logs carry only an event name and
status code. `close({ deadlineMs })` stops accepting connections, lets requests finish and closes what is left at the
deadline.

## Hosted service

`src/main.ts` is the process; `startHosted({ env, transport, log })` in `src/entry.ts` does the work:

1. `hostedConfigFromEnv(env)` reads `KEYSENTRY_CONTROL_ORIGIN`, `KEYSENTRY_CONTROL_BUCKET`, `KEYSENTRY_STRIPE_PRICE_ID`,
   `KEYSENTRY_BOX_PROJECT_ID`, `KEYSENTRY_BOX_SERVICE_ACCOUNT`, `KEYSENTRY_BOX_ALLOWED_DIGESTS` (comma list),
   `KEYSENTRY_TRUSTED_PROXY_HOPS` (default 1), `KEYSENTRY_BOX_QUOTA` (default 1), `PORT` (Cloud Run sets it), and the
   Secret Manager references `KEYSENTRY_STRIPE_WEBHOOK_SECRET_REF` and `KEYSENTRY_STRIPE_API_KEY_REF`
   (`projects/P/secrets/S/versions/V`). With `KEYSENTRY_CONTROL_PLANE_LIVE=1` it also reads `KEYSENTRY_BOX_ZONE`,
   `KEYSENTRY_BOX_SUBNETWORK` (in the box project and the zone's region) and `KEYSENTRY_BOX_IMAGE_REFERENCE` (digest
   in the allowed list). A plaintext `KEYSENTRY_STRIPE_WEBHOOK_SECRET` or `KEYSENTRY_STRIPE_API_KEY` refuses to start.
   Errors name the variable, never its value.
2. Both references are read with `GET https://secretmanager.googleapis.com/v1/{reference}:access` and the metadata
   token, the CRC32C checked, one trailing newline dropped, and the values checked to look like a Stripe webhook secret
   and a Stripe secret or restricted key. The values stay in memory.
3. The hosted composition listens on `0.0.0.0:PORT`.

Network clients, each wrapping the fetch transport:

| Client | Reaches |
|---|---|
| Hosted (egress guard: HTTPS only, DNS names only, no redirects) | `storage.googleapis.com` (this bucket's objects only), `api.stripe.com` (`GET /v1/subscriptions/{id}`, `POST /v1/checkout/sessions`), `www.googleapis.com` (the Confidential Space JWKS URL only) and, only with live provisioning, `compute.googleapis.com` in `projects/BOX_PROJECT/zones/ZONE`: `POST .../instances`, `GET .../instances/NAME`, `POST .../instances/NAME/stop` and `POST .../instances/NAME/start` |
| Metadata | `GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` with `Metadata-Flavor: Google`, nothing else |
| Secret Manager (startup only) | `GET` the `:access` URL of the two configured references, nothing else |

Logs are one JSON line per event on stdout: `{"event":"request","status":200}`, `started`, `stopping`, `stopped`
(status 0), and on failure `config-invalid` or `secret-unavailable` (status 1, with the variable name in `setting`),
`listen-failed`, `stop-failed`, `crashed`. No path, address, header, token or upstream text is logged. On SIGTERM the
server stops accepting connections, lets requests finish for up to 8 seconds (Cloud Run sends SIGKILL after 10) and
exits.

## Image

`Dockerfile.control-plane` uses the same pinned `node:24-alpine` and distroless `nodejs24-debian13:nonroot` digests as
`Dockerfile`, for `linux/amd64`. The build stage copies only the root manifests, `src/` and this package's `src`,
`scripts` and `ui`, then runs `scripts/build.mjs`, which refuses out-of-date page assets and bundles `src/main.ts` with
esbuild, checking every bundled module against `scripts/bundle-policy.mjs` (never the watcher, CLI, box agent, box
sealing, dashboard or emulator). The runtime stage holds `/app/control-plane.mjs`, `LICENSE` and `NOTICE`, runs as user
65532 and starts `/nodejs/bin/node /app/control-plane.mjs`.

The bundle also carries some provider and vault modules: `src/box/handshake` imports the `src/security/index.ts`
barrel, whose audit module imports `src/vault/keys.ts`. They are never called by the control plane.

## Emulator and provisioning

`startEmulator({ policy?, now?, startBox? })` serves attestation, JWKS, STS, KMS and Compute on one `127.0.0.1` port.
Every request must carry the exact loopback Host; token minting, STS, KMS and Compute also require a random per-start
secret held only by the emulator's own `http` client. Compute accepts only what Confidential Space would run as a
keysentry box and calls the injected `startBox(config)`; it never starts a VM. It also models `instances.get` (the
instance's status and metadata, or 404) and `instances.stop` and `instances.start` (no request body; they change only
the recorded status).

`createProvisioner({ ..., relayOrigin })` creates the Terraform-shaped TDX instance with metadata
`tee-image-reference`, `tee-restart-policy`, `keysentry-box-id`, `keysentry-relay-origin` and
`keysentry-enroll-device-key` (non-secret routing, read by `readBoxRoute`). `inspect(name)`, `stop(name)` and
`start(name)` call `instances.get`, `instances.stop` and `instances.start` (stop and start with an empty body). Failures
are a `ProvisionError` with fixed text and an `outcome`: `refused` when no instance can have been created, `unknown`
otherwise. It refuses live calls unless `KEYSENTRY_CONTROL_PLANE_LIVE=1` and an access-token provider are supplied.
Network, firewall, box IAM and KMS are prerequisites (`infra/terraform/box`).

`startLocalBox({ bootBox, boxId?, enrollmentDeviceKey? })` runs the emulator, a loopback control plane and one box
provisioned through emulator Compute. `close()` closes both listeners even if the box fails to stop.

## Deploy steps (written, not run)

Prerequisites: a control-plane project and the box project (`infra/terraform/box` applied there), billing enabled,
these APIs enabled in the control-plane project: Cloud Run, Secret Manager, Cloud Storage, IAM, Artifact Registry
(and Compute in the box project for live provisioning). Use Stripe test mode end to end first.

1. **Stripe (test mode).** Create the product and a recurring price (`price_...`). Create a restricted key with
   Checkout Sessions: Write and Subscriptions: Read. Create the webhook endpoint `https://ORIGIN/billing/webhook` for
   `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `checkout.session.async_payment_failed`,
   `customer.subscription.updated`, `customer.subscription.deleted`, and copy its signing secret. Set the failed-payment
   setting to end in `unpaid` or `canceled`.
2. **Secrets.** In the control-plane project, create two secrets (for example `keysentry-stripe-webhook` and
   `keysentry-stripe-api-key`) and add one version each, without a trailing newline, e.g.
   `printf '%s' "$VALUE" | gcloud secrets versions add keysentry-stripe-webhook --data-file=- --project=$PROJECT`.
3. **Image.** From a clean checkout:
   `docker build -f Dockerfile.control-plane --build-arg KEYSENTRY_BUILD_COMMIT=$(git rev-parse HEAD) -t $REGION-docker.pkg.dev/$PROJECT/$REPO/control-plane:$COMMIT .`,
   push it, and take its digest (`...@sha256:...`).
4. **Origin.** Decide the final public origin now (passkeys are bound to its host name). Either a custom domain mapped to
   the service, or the service's `run.app` URL (known after the first apply; then set `public_origin` and apply again
   before anyone signs up).
5. **Terraform.** In `infra/terraform/control-plane`: `terraform init`, then `terraform plan` with `project_id`,
   `region`, `bucket_name`, `image_reference` (digest), `public_origin`, `stripe_price_id`, `stripe_webhook_secret_id`,
   `stripe_api_key_secret_id`, `box_project_id`, `box_service_account_email`, `allowed_image_digests` (from the signed
   allow-list), `trusted_proxy_hops` (2 behind an external Application Load Balancer) and `live_provisioning = false`.
   Review, then `terraform apply`.
6. **Check.** `curl https://ORIGIN/health` → `{"ok":true}`; logs show `{"event":"started","status":0}` (a
   `config-invalid` or `secret-unavailable` line names the setting to fix). Open `https://ORIGIN/`, create an account with
   a passkey, start checkout, pay with Stripe's test card, and confirm the webhook turns the plan to paid; sign out and
   sign in again.
7. **Live provisioning.** Set `live_provisioning = true`, `box_zone`, `box_subnetwork`
   (`projects/BOX_PROJECT/regions/REGION/subnetworks/NAME-subnet`) and `box_image_reference` (digest in the allowed list);
   apply. Create one box from the page with the key from `keysentry box card`; check the instance in the box project. If
   `instances.insert` answers 403, the reply names the missing permission: add it to the custom role.
8. **Live mode.** Repeat 1–2 with live Stripe keys and a new webhook secret; add secret versions (the service reads
   `latest` at startup, so redeploy or restart it after a rotation).
9. **Rollback.** Apply again with the previous `image_reference` digest. The bucket keeps state across revisions.

