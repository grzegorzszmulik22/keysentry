# keysentry control plane — not deployed

Private Apache-2.0 package for the cloud-box control plane and its local emulator. Nothing in this package has been
deployed, and no test calls Google, Stripe or any other external service. Node >=22.13 is required. The package
declares no dependencies of its own; the shared repository modules it imports (WebAuthn, box handshake schemas,
attestation verifier, security primitives) bring the root's dependencies with them, for example zod through
`src/box/handshake`. It never imports the watcher, CLI, vault or providers.

## What is built, and what is not

Built and tested locally (fakes and the loopback emulator):

- Passkey accounts with durable sessions (stored by hash), per-account session caps and bounded challenges.
- Stripe webhooks that grant the paid plan only for a paid subscription to the configured price, confirmed through
  the Stripe API, and revoke it on failed payments and subscription status changes.
- `POST /boxes` gated by the paid plan, a per-account box quota and a name reservation before any Compute call.
- The relay: handshake messages, the approval and disarm wire formats the code base emits, ciphertext blobs, per-box
  serialization and per-box and global byte quotas.
- Box authentication by Confidential Space attestation token (hosted) or issued bearer (emulator and tests).
- Rate limits keyed by credential or by the client address a configured front end reports.
- Storage in memory, in a private directory, or in a Cloud Storage bucket through the JSON API.
- `createHostedControlPlane(hostedConfigFromEnv(env))`: the hosted composition, and a Terraform module that passes
  exactly that environment.

Not built, so the hosted service is **not launch-ready**:

- No container image or process entry point for Cloud Run. The entry must create the egress-guarded HTTPS client and
  a metadata-only client (see `notes/control-plane.md`), then call `createHostedControlPlane(...).listen()`.
- No browser UI, no Stripe Checkout creation and no billing pages.
- Live box provisioning is not wired into the hosted composition (`POST /boxes` answers 503 there) and Terraform grants
  the service no Compute or service-account-user rights. The provisioner still refuses live calls unless
  `KEYSENTRY_CONTROL_PLANE_LIVE=1` and an access-token provider are supplied.
- One instance only: per-box and per-account work is serialized in process and Cloud Storage writes have no
  compare-and-swap, so Terraform pins `max_instance_count = 1`. A revision rollout can briefly run two instances.

## Local validation

Run from the repository root:

```powershell
node tools/vitest-sandbox.mjs packages/control-plane/test
node tools/vitest-sandbox.mjs tools/probes/phase4/control-plane
npx tsc -p packages/control-plane/tsconfig.json --noEmit
node tools/vitest-sandbox.mjs test/infra/terraform.test.ts
```

The root TypeScript project and ordinary root Vitest configuration do not include this package. CI must include the
package test path and typecheck explicitly.

## Storage

`Storage` is `get`, `put`, `delete`, `list(prefix)` over JSON records with keys of at most 150 characters
(`[A-Za-z0-9_-]` segments joined by `/`).

- `createMemoryStorage()`.
- `createFileStorage(directory)`: one private directory, lower-case base32 file names (so case-folding file systems such
  as NTFS and default APFS never alias two keys), exclusive temporary files, fsync and atomic rename, symlinks refused,
  reads sized to the file. Windows deployments must supply the directory ACLs.
- `createGcsStorage({ http, bucket, accessToken, objectPrefix? })`: one object per key over the Cloud Storage JSON API
  through the injected `HttpClient`, bounded retries with backoff on 429 and 5xx, fixed error text.
  `metadataAccessToken(http)` reads the service account's token from the metadata server and caches it.

## Relay

`createRelayStore({ storage, now?, ...limits })` exposes `publish`, `poll`, `putBlob`, `getBlob` and `sweep`. Work is
serialized per box, so one box never delays another. Each box has an index record (`relay-index/<box>`: queue size and
count, and each blob's size and expiry), so quotas never read blobs; global usage is rebuilt from index records once
per process. `sweep()` visits a bounded batch of boxes per call (64 by default) and the server runs it every minute.

Accepted messages:

- The five handshake messages, validated with the shared strict schemas, signed lifetime exactly ten minutes.
- Approvals exactly as `publishApproval` sends them: `{"type":"keysentry-approval","v":1,"approval":{"actionId",
  "keyId","digest","at","sig"}}`, relayed only while `at` is within the verifier's ten-minute window.
- Disarms exactly as `publishDisarm` sends them: `{"type":"keysentry-disarm","v":2,"watcherId","keyId","at","sig"}`.
  `at` takes the same two forms as `validAt` (with or without milliseconds). The relay does not bind `watcherId` to the
  box id (the CLI signs with the project id); the watcher checks its own id and the signature. An old disarm is
  delivered, with a storage TTL from receipt.

The relay validates shape, encoding, size and expiry only; endpoints verify signatures, attestation and authority.

Default limits: message 1 MiB; queue 128 messages and 4 MiB per box; blob 2 MiB decoded, 128 blobs and 16 MiB stored
per box; 64 MiB for every box's queues and blobs together (507 when full); ten-minute delivery TTL; blob TTL at most
24 hours. These are far below the 512 MiB Cloud Run memory, and with Cloud Storage the bytes live in the bucket.

## Accounts

`createAccounts({ storage, origin, ... })` reuses `verifyRegistration` and `verifyAssertion` with user verification
and one-use challenges, and refuses counter regression and cross-account credential reuse.

- Sessions are stored as `sessions/<sha256(id)>` (the id itself is never stored), with a 30-minute sliding idle expiry
  (written at most once a minute) and a 12-hour absolute lifetime. A sign-in beyond 8 sessions evicts that account's
  oldest. A restart or scale-to-zero keeps everyone signed in.
- The cookie is `__Host-ks_control_session` over HTTPS (`Path=/; HttpOnly; SameSite=Strict; Secure`), so a sibling
  subdomain can neither plant nor shadow it; loopback HTTP uses `ks_control_session` without `Secure`.
- Challenges stay in memory: 2-minute TTL, at most 16 pending per client address (a new one evicts that client's
  oldest) and 20,000 in total (oldest evicted).
- Registration writes the account, credential index, session and session index, and deletes all of them if any write
  fails, so a refused registration never burns the passkey.
- `reserveBox` (402 unpaid, 403 at quota, 409 name held by another account) writes a pending ownership record;
  `confirmBox` makes it active; `releaseBox` rolls a pending one back. The quota (default 1) counts pending and active
  boxes. `ownsBox` and `boxOwner` see active boxes only.

## Billing

`createBilling({ storage, accounts, endpointSecret, priceId, stripe: { http, apiKey } })` verifies the raw bytes
(HMAC-SHA256, any `v1`, one `t`, ±300 s) and keeps a durable event-id replay record, written only after the event was
handled.

| Event | Effect |
|---|---|
| `checkout.session.completed`, `checkout.session.async_payment_succeeded` | Paid only for `mode: subscription`, `status: complete`, `payment_status` `paid` or `no_payment_required`, an existing account (`client_reference_id` or `metadata.accountId`), and a subscription that `GET /v1/subscriptions/{id}` reports `active` or `trialing`, for the same customer, with the configured price. If Stripe cannot be reached the webhook answers 503 and Stripe retries. |
| `checkout.session.async_payment_failed` | Free, when that checkout's subscription is the account's current one. |
| `customer.subscription.updated` | For the account's current subscription: `unpaid`, `canceled`, `incomplete_expired`, `paused` or another price revoke; `active` and `trialing` with the configured price grant; `past_due` keeps the plan while Stripe retries; `incomplete` changes nothing. An event older than one already applied is ignored; a grant needs the event's `created` time. |
| `customer.subscription.deleted` | Free, for the account's current subscription. |

The paid plan gates creating boxes; it does not stop running ones. `apiKey` should be a restricted key that can only
read subscriptions. Checkout creation and the billing UI are not built.

## HTTP server

`createControlPlaneServer({ origin, accounts, billing, relay, provisioner?, boxAttestation?, trustedProxy?, ... })`
returns `listen`, `close`, `issueBoxToken(boxId)` and `revokeBoxToken(boxId)`. The public Host must equal the origin
(DNS rebinding is refused). Pass `accounts: origin => createAccounts(...)` for a random-port origin.

| Method | Route | Access |
|---|---|---|
| GET | `/healthz` | Public |
| POST | `/auth/register/challenge`, `/auth/register/finish`, `/auth/login/challenge`, `/auth/login/finish` | Same-origin passkey ceremonies |
| GET, DELETE | `/session` | Session; delete also requires Origin and CSRF |
| POST | `/billing/webhook` | Stripe signature over the raw bytes |
| POST | `/boxes` | Owner session, Origin and CSRF; body `{ "name", "deviceKey" }` |
| GET, POST | `/boxes/:boxId/messages` | Owner session, or that box's attestation token or issued bearer |
| POST | `/boxes/:boxId/blobs` | Same |
| GET | `/boxes/:boxId/blobs/:blobId` | Same |

`POST /boxes`: `name` must be a Compute instance name (`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`, not `gcp-`) and
`deviceKey` the owner's enrollment device public key (Ed25519 SPKI DER, base64, 44 bytes); otherwise 400. Then the
plan, quota and name are checked and the name reserved (402, 403, 409) before the provisioner is called; a failed
provision releases the reservation and answers 502.

Box access: a hosted box presents a Confidential Space token for this server's origin (`relayCredential` in
`src/box/agent/main.ts`). It is checked by the shared verifier against `boxAttestation`'s JWKS (or the pinned PKI root),
issuer, audience, time (at most an hour old), secure boot, `dbgstat`, `swname`, `STABLE`, hardware, memory monitoring
off, no overrides, project, service account and allowed digest; nonces are not involved. `submods.gce.instance_name`
must name the box in the route, and the box must exist (default: it has an active owner). Verified tokens are cached
until they expire; a forced JWKS refresh runs at most every five minutes. Issued 43-character bearers remain for the
emulator and tests; issuing a new one replaces the box's previous bearer.

Rate limits (token buckets, least recently used evicted beyond 10,000): per box credential (120 a minute), per signed-in
account (120), per client address for anonymous requests and failed credentials (120), and `/billing/webhook` per client
address (300). The client address is the socket peer, or with `trustedProxy: { header, hops }` the entry `hops` from the
right of that header (2 behind an external Application Load Balancer); IPv6 addresses count per /64. A request whose
credential needs a storage read or a signature check is charged to its client address first. Connections: at most 1,024,
and 64 per socket address without a trusted proxy. A refused or unread request body is not drained; the response closes
the connection. Bodies are JSON only (2 MiB default, up to 4 MiB; auth 64 KiB; webhook 256 KiB). Logs carry only an
event name and status code.

## Hosted configuration

`hostedConfigFromEnv(env)` reads, and `infra/terraform/control-plane` sets: `KEYSENTRY_CONTROL_ORIGIN`,
`KEYSENTRY_CONTROL_BUCKET`, `KEYSENTRY_STRIPE_PRICE_ID`, `KEYSENTRY_BOX_PROJECT_ID`, `KEYSENTRY_BOX_SERVICE_ACCOUNT`,
`KEYSENTRY_BOX_ALLOWED_DIGESTS` (comma list), `KEYSENTRY_TRUSTED_PROXY_HOPS`, and from Secret Manager
`KEYSENTRY_STRIPE_WEBHOOK_SECRET` and `KEYSENTRY_STRIPE_API_KEY`; Cloud Run sets `PORT`. Errors name a missing
variable, never its value. The Terraform service is public (`invoker_iam_disabled`; every route authenticates its own
caller), one instance, 512 MiB, with object access to the private versioned bucket (old versions deleted after 7 days;
relay and session objects after 2 days) and read access to the two Stripe secrets only.

## Emulator and provisioning

`startEmulator({ policy?, now?, startBox? })` serves attestation, JWKS, STS, KMS and Compute on one `127.0.0.1` port.
Every request must carry the exact loopback Host. Token minting, STS, KMS and Compute also require a random per-start
secret held only by the emulator's own `http` client; JWKS, the PKI root and health are public. `mintToken` names
`instanceName` in `submods.gce.instance_name`. Compute accepts only what Confidential Space would run as a keysentry box
(TDX on C3, secure boot, TERMINATE, the production image family, no external address, the box service account, and
exactly the five metadata keys below) and calls the injected `startBox(config)`; it never starts a VM.

`createProvisioner({ ..., relayOrigin })` creates the Terraform-shaped TDX instance with metadata
`tee-image-reference`, `tee-restart-policy`, `keysentry-box-id`, `keysentry-relay-origin` and
`keysentry-enroll-device-key` (non-secret routing, read by `readBoxRoute`). Network, firewall, IAM and KMS are
prerequisites.

`startLocalBox({ bootBox, boxId?, enrollmentDeviceKey? })` runs the emulator, a loopback control plane and one box
provisioned through emulator Compute. Its relay accepts the box's emulator attestation token exactly as the hosted relay
does, and `cliToken` is an issued bearer for the CLI. `close()` closes both listeners even if the box fails to stop.
