# keysentry control plane — not deployed

Private Apache-2.0 package for the phase 4 cloud-box control plane and local emulator. Nothing in this package has
been deployed. Tests use local fakes; they do not call Google, Stripe or any other external service. Node >=22.13
is required. There are no package dependencies to install; shared TypeScript modules resolve from the repository.

The control plane provides passkey accounts, account-owned boxes, a relay for the five signed handshake messages
and signed approval/disarm documents, expiring ciphertext blobs, Stripe billing hooks, provisioning and health.
Its public TypeScript API is exported from `src/index.ts`. It never imports the watcher, CLI, vault or providers.

Provider tokens and device unlock shares are encrypted by the CLI before relay publication. The relay never
decrypts them. It stores public handshake keys, attestation documents, signatures, ciphertext, hashes and expiry
metadata. Account records contain public passkey credentials and plan/ownership metadata. Stripe request bodies
and session, challenge and box bearer tokens are not persisted. Structured server logs contain only an event name
and status code. An opaque ciphertext format cannot establish that an untrusted caller actually encrypted its
input; callers must use the shared handshake/sealing code and keep secrets out of metadata and signed documents.

## Local validation

Run from the repository root:

```powershell
node tools/vitest-sandbox.mjs packages/control-plane/test
npx tsc -p tsconfig.json --noEmit
npx tsc -p packages/control-plane/tsconfig.json --noEmit
```

The root TypeScript project and ordinary root Vitest configuration do not include this separate package. CI must
include the package test path and package typecheck explicitly. The prescribed sandbox runner disables the root
Vitest configuration and discovers these tests. From this directory, `npm test` and `npm run typecheck` also work
with the repository's already installed tooling.

## Services and storage

`createMemoryStorage()` and `createFileStorage(directory)` implement `Storage` (`get`, `put`, `delete`, `list`). The
file implementation uses encoded flat filenames, private modes where supported, exclusive temporary files,
fsync and atomic rename. It rejects symlink records and bounds JSON reads. The configured directory must be
private; Windows deployment must supply its filesystem ACLs. Atomic writes protect individual records. This is
a single-process store, with no cross-process transactions or distributed replay lock.

`createRelayStore({ storage, now? })` exposes `publish`, `poll`, `putBlob`, `getBlob` and `sweep`. Handshake messages
use the existing strict schemas. Approval/disarm wrappers match the existing approval relay wire format:

```json
{"type":"keysentry-approval","v":1,"approval":{"actionId":"...","keyId":"...","digest":"...","at":"...","sig":"..."}}
```

Disarms use `type: "keysentry-disarm"` and a `disarm` object with `watcherId`, `keyId`, `at`, `sig`. The watcher ID
must match the box queue. The relay validates schema, encoding, size and expiry; the CLI/box verifies signatures,
attestation, transcript links and authority. It never treats relay acceptance as authorization.

Queues are per box and can be filtered by session ID. Polling is non-destructive so both endpoints can read the
transcript. Duplicate queued IDs are refused. Defaults: ten-minute delivery TTL, 128 messages and 7 MiB per queue,
2 MiB per message, 128 blobs per box and 2 MiB decoded bytes per blob. Blobs carry
`{ kind: 'sealed-bundle' | 'sealed-state', ciphertext: <canonical base64url>, ttlMs? }`; TTL cannot exceed 24 hours.
Handshake TTL cannot extend signed expiry. Old valid disarms can be delivered because disarming removes authority;
their storage TTL begins at receipt. Expired entries are inaccessible immediately and removed lazily or by the
server's minute sweep. TTL cleanup resumes when the process runs again.

`createAccounts({ storage, origin, ... })` reuses `verifyRegistration` and `verifyAssertion`, requires user
verification and one-use challenges, rejects assertion counter regression, and creates idle-expiring sessions.
Cookies use `Path=/; HttpOnly; SameSite=Strict` and `Secure` for HTTPS. Loopback HTTP is allowed for the emulator.
Sessions/challenges stay in memory and disappear on restart. Ownership cannot be reassigned to another account.

`createBilling({ storage, accounts, endpointSecret, now? }).handle(rawBody, stripeSignature)` verifies the original
bytes using HMAC-SHA256, constant-time comparisons, multiple `v1` signatures and a 300-second tolerance. Event IDs
provide durable replay detection. Checkout completion marks an existing account paid; subscription deletion
marks the matching current subscription free. Unknown events are acknowledged without changing a plan. A
checkout identifies its account through `client_reference_id` or `metadata.accountId`; customer/subscription
references are remembered for deletion. There is no checkout creation, Stripe API client or billing UI.

## HTTP server

`createControlPlaneServer({ origin, accounts, billing, relay, provisioner?, port?, ... })` returns `listen`, `close`,
`issueBoxToken(boxId)` and `revokeBoxToken(boxId)`. The default listener is loopback. An HTTPS public origin assumes
TLS termination outside this Node HTTP listener. Public Host must match that origin. Use `origin:
"http://127.0.0.1:0"` for a random local port and pass `accounts: actualOrigin => createAccounts({ storage, origin:
actualOrigin })` so WebAuthn uses the finalized origin. A fixed-origin service can pass an account object directly.

| Method | Route | Access |
|---|---|---|
| GET | `/healthz` | Public JSON health |
| POST | `/auth/register/challenge`, `/auth/register/finish` | Same-origin passkey registration |
| POST | `/auth/login/challenge`, `/auth/login/finish` | Same-origin passkey assertion |
| GET, DELETE | `/session` | Session; delete also requires Origin/CSRF |
| POST | `/billing/webhook` | Stripe signature over raw JSON bytes |
| POST | `/boxes` | Owner browser session, Origin and CSRF; body `{ "name": "..." }` |
| GET, POST | `/boxes/:boxId/messages` | Owner session or scoped box bearer |
| POST | `/boxes/:boxId/blobs` | Owner session or scoped box bearer |
| GET | `/boxes/:boxId/blobs/:blobId` | Owner session or scoped box bearer |

Message GET accepts only the optional `?sessionId=...` query. Browser writes require the session's
`X-CSRF-Token` and exact Origin. Authentication responses include `csrf`; binary WebAuthn inputs use base64url.
Bearer capabilities authorize only their named box, are returned only to the trusted embedding runtime, and
are held as hashes in server memory. Issuing a replacement invalidates the prior capability. The runtime must
deliver it privately to its injected box and re-enroll after a server restart; it must never put it in instance
metadata or URLs. Provisioning remains browser-session-only.

HTTP requests are JSON only, use the approval server's security headers, enforce streamed/body length limits and
per-socket-client rate limits, and do not trust `X-Forwarded-For`. Default HTTP body limit is 2 MiB (configurable
up to 4 MiB), auth 64 KiB and webhook 256 KiB. A larger blob's base64 representation must also fit the HTTP limit.

## Emulator and provisioning

`startEmulator({ policy?, now?, startBox? })` starts one server on `127.0.0.1` at a random port, with separate
attestation, JWKS, STS, KMS and Compute routes. `close()` stops it and clears retained KMS keys/access grants.
The injected `HttpClient` maps the official Google STS/KMS/Compute URLs to this listener and refuses every other
destination; it makes no external calls. The local attestation endpoint mirrors the launcher's JSON token request
and raw JWT response. Keys and a root/intermediate/leaf PKI chain are generated locally in memory.

```typescript
const emulator = await startEmulator({
  startBox: async config => { /* Inject the later box agent here; config contains public instance settings. */ },
});
const provisioner = createProvisioner({
  http: emulator.http,
  emulatorOrigin: emulator.computeOrigin,
  projectId: emulator.policy.projectId,
  zone: 'us-central1-a',
  subnetwork: `projects/${emulator.policy.projectId}/regions/us-central1/subnetworks/box-subnet`,
  serviceAccount: emulator.policy.serviceAccount,
  imageReference: `registry.invalid/keysentry/box@${emulator.policy.allowedDigests[0]}`,
  allowedDigests: emulator.policy.allowedDigests,
});
try { await provisioner.provision({ name: 'local-box' }); }
finally { await emulator.close(); }
```

`mintToken({ audience, nonces, tokenType?, switches? })`, `setSwitches` and `updateReleasePolicy` support tests.
Switches: `debugImage`, `otherProject`, `otherServiceAccount`, `missingStable`, `wrongDigest`, `staleIat`, `replay`.
Use the emulator's `jwks`/`root` explicitly with the shared verifier; these are local trust anchors, never Google's.
STS verifies the local RS256 signature, time and release policy. KMS rechecks the current policy on each operation:
allowed digest, project, service account, Confidential Space, STABLE and production debug status. AES-GCM wrapping,
AAD, checksums and bearer expiry are enforced. This models release-policy behavior, not Google's hardware or IAM.

Provisioning emits Terraform-matching TDX/c3-standard-4 settings, secure boot, production Confidential Space,
TERMINATE maintenance, private subnet and no external address or secret metadata. Existing network, firewall,
IAM and KMS infrastructure are prerequisites. Without a trusted loopback emulator origin, provisioning refuses
unless `KEYSENTRY_CONTROL_PLANE_LIVE=1` and a live access-token provider are supplied. That flag is never set in
this project. No resources have been created. Compute invokes only the injected `startBox(config)`; it does not
start a VM or a watcher by itself.
