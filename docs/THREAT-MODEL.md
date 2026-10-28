# keysentry 1.0 threat model

keysentry needs access to secret values to compare their copies and replace them. This is a local
CLI, loopback dashboard and optional watcher that you host. You choose the projects and credentials they can
use. Its [trust promise](superpowers/specs/2026-10-27-trust-autopilot-design.md#3-the-trust-promise)
guides the design; the [access guide](ACCESS.md) describes the actual integration permissions.

This model covers 1.0 phases 1–3: vault storage, encrypted state, network restrictions, an audit log,
rotation recovery, human confirmation, release tooling, signed breach autopilot, notifications, approvals and
the self-hosted watcher, plus local first run, the dashboard, guard, hygiene and shareable reports. There has been **no external security
audit**. Adapter behaviour has **not yet been tested against live accounts**. Fake API tests and
source review can check our decisions and formats, but cannot establish every provider's live
permission or deployment behaviour.

## Assets

| Asset | Why it matters | Where it is permitted |
|---|---|---|
| Hosting and provider credentials | Can reveal configuration, create or disable keys, or deploy code within their scopes. | OS vault, explicitly chosen encrypted-file vault, or a supported environment source; plaintext while needed in memory and in authorized API headers/bodies. |
| Existing and replacement secret values | Applications need them; losing a replacement can interrupt a rotation. | Original host/provider, process memory, and encrypted per-rotation records while recovery or undo needs them. |
| State and fingerprint keys | Allow saved inventory to be decrypted and copies of a value to be matched. | Vault; in memory while used. |
| Inventory, plans, journal, hints, service names | Describe infrastructure even without full secret values. | Encrypted project state. Exported reports and terminal output need the user's own care. |
| Audit chain, MAC key and device signing key | Help detect changes to the recorded history. | Secret-free audit metadata in a local log; MAC key, signing key and known head in the vault. |
| Release signing key and trusted public keys | Determine which published checksum signatures users accept. | Private key in the maintainer's release secret store/signing process; public trust list in the source and bundle. |
| Running applications | A mistimed change or revocation can stop them. | Hosting platforms controlled by the user; modified only through an approved rotation. |
| Signed armed plan | Authorizes specific automatic rotations, consumer scope, limits and expiry. | Encrypted local/watcher state and sealed deployment configuration; verified against trusted device keys before effects. |
| Approval credentials, challenges and grants | Authorize one narrowly bound action without sharing application secrets. | Public passkey credentials and single-use approval state in encrypted storage; challenges/assertions in the approval flow; signed device messages through the relay. |
| Watcher deployment/state keys and vault passphrase | Unlock the sealed configuration, saved state and recovery values. | Platform secret settings and process memory; never beside encrypted state or in committed config. The watcher host can access them while running. |
| First-run findings | Reveal key hints, file/history locations and possible deployment platforms. | Terminal/process memory; an explicitly saved pre-vault summary in `.keysentry/` is metadata, not encrypted credential storage. `--no-save` writes nothing. |
| Dashboard sign-in token, session, CSRF token and passkey proof | Authorize local browser reads and exact changes. | One-time token in the initial localhost URL, then an HttpOnly session cookie; CSRF/proof in the local browser and server. They are never included in reports or receipts. |
| Share card and timeline exports | May disclose preparation, infrastructure or incident timing even without key values. | Local SVG/Markdown or browser image/clipboard; external publication is the user's choice. Card platform/count statistics require separate opt-ins. |

## Boundaries and controls

**Your terminal to the CLI.** Manual mutation requires the interactive human path. Known coding-agent
markers are refused even if a TTY is present. Read-only commands can be run by an agent at your
request and return metadata, not values. `watch` and `watch --once` refuse those markers without requiring a TTY;
their effects require signed armed-plan scope or a specific approval. There is no MCP server or agent skill in the
product. Environment marker detection is an extra check; it is not an identity proof or an OS
access boundary.

**The project to first run and guard.** Token-free first run needs no vault or credentialed runtime. It reads
bounded local candidate files and Git history without a network request, consumes transient plaintext into
keyed fingerprints/hints and returns metadata. Git is spawned without a shell, hooks or external diff/text
conversion helpers, using a minimal environment; lazy fetching is disabled. A per-run random key avoids a
stable unsaved fingerprint identity. An initialized project can reuse its project key. `--no-save` writes
nothing; creating `.keysentry/` first needs consent. Before vault initialization, an explicitly saved summary
is plaintext metadata containing hints/locations, not plaintext credential values. Protect that directory as
infrastructure information. Package acquisition by `npx` can contact the registry before this scanner runs.

File size, count and history budgets, ignored directories, unavailable partial-clone objects, binary/encoded
content and lightweight parsing limit coverage. Incomplete history is reported. Removing a value from current
files does not remove it from Git history or revoke it. Guard uses the classifier on staged additions and can
miss unknown or reconstructed values. Its optional hook calls an installed binary without downloading code;
if that binary is missing, the commit is not checked. A user can also bypass a Git hook. Allow-list hashes are
for synthetic fixtures only and permit offline guesses; broad path exceptions exempt everything they match.

**The browser to the local dashboard.** The dashboard binds only `127.0.0.1`, opens as
`http://localhost:<random port>` and exchanges a random, two-minute, single-use URL token for an HttpOnly,
SameSite=Strict session cookie. Cookie names include the port to avoid cross-project replacement; cookies
themselves are not isolated by port. Exact Host checks constrain DNS rebinding. POST requests also need the
exact localhost Origin and session CSRF token. The server sends no CORS permissions, bounds JSON input and
serves only bundled assets under a strict CSP with no inline scripts/styles or external resources. Authenticated
idle sessions and the server expire after 15 minutes by default. The initial URL is a bearer credential until
used or expired; a process able to steal it first can establish the browser session. The CLI opens a 0600 HTML launcher in the private user directory instead of passing the token to the browser in process arguments. It deletes the file after two minutes. Normal output contains only the file path; an explicitly requested `ui --print-url` at a human terminal exposes the bearer URL to that terminal and its capture history. Same-user processes can still read the launcher.

Every dashboard change and explicit reveal requires a fresh passkey assertion with user verification, bound
to that session, exact route and canonical request-body digest. A proof expires after two minutes and is
consumed once; altered input, replay and clone-warning counters fail closed. Passkeys are registered only
with `keysentry passkey register` at a human terminal. The dashboard has no registration routes: an agent
driving a browser could otherwise add its own virtual authenticator, claim user verification and authorize
changes. CLI and dashboard share the encrypted project `passkeys.json` array, including assertion counters.
Earlier plaintext CLI records and vault `passkey/*` records migrate to that file once; plaintext state is
refused afterwards. The relying party is `localhost`; assertion verification checks the current full origin,
including port. Approval dialogs show the proposed changes and bind approval to the displayed review hash.

Agent-marked launches run read-only, with no key changes. Previews and drills can still save encrypted metadata.
Disarm deliberately works without a passkey even there and cancels arming still in progress. Someone with an
authenticated session can therefore stop future automatic work, but cannot re-arm without authorization or
restore already revoked keys. Browser/authenticator implementations, terminal enrollment and human review
remain trust boundaries. An unrestricted same-user agent or compromised browser may access storage/processes
or manipulate the trusted code directly.

Normal reads return only metadata/hints. Explicit reveal rereads a readable consumer, needs confirmation and
passkey authorization, and audits only the variable name and cluster ID. Write-only values cannot be revealed.
Revealed text is cleared when the page disposes it. Clipboard copy attempts clearing after 30 seconds, but
browser permissions, tab closure/suspension, extensions or clipboard history can retain a copy. Clearing the
current clipboard cannot remove copies already captured elsewhere. Same-user processes remain able to inspect
an authorized browser or its memory. The session/passkey store has no cross-process transactional lock; one
active dashboard writer per project is required.

**Local reports to sharing.** The SVG card shares only score and branding by default; platform and
completed-rotation counts require independent opt-ins. It has no values, hints, key names, project names,
scripts, external references or arbitrary markup. The browser renders it as a Blob image, never injected SVG.
A score describes recorded preparation, not proof of live recovery or a guarantee about security. Timeline
Markdown escapes/redacts selected events but can still disclose incident times, service-related metadata or
operational outcomes. Exports stay local until shared. Review exported metadata; a public post cannot be
recalled by changing the local file. No card opt-in makes key values eligible for export.

**The CLI to storage.** Credential values go to macOS Keychain, Windows DPAPI under the current
user, or Linux Secret Service. If those are unavailable, the user must choose the encrypted-file
fallback; it uses scrypt and AES-256-GCM. Environment credentials are allowed for workflows that
need them and are identified as weaker.

State uses AES-256-GCM authenticated encryption with a vault-held key. Authentication binds each encrypted file
to its kind and its path within `.keysentry`; journal records also carry an authenticated sequence number and the
hash of the previous sealed line, so reordering, deletion in the middle and record substitution are detected. A
vault entry binds the project directory to its original project ID, and a vault marker closes the one-time 0.1
plaintext migration: after it, any unencrypted file that appears in saved state is rejected, never migrated.
`project.json`, `.gitignore`, `audit.jsonl` and `network.jsonl` are plaintext by design. The read-only environment
vault (CI, the watcher) never migrates plaintext; its project binding lasts only for one process. Copying encrypted
state to another machine without its key does not make it readable, and unreadable files are not silently
overwritten. These checks do not establish freshness: an older valid file at the same path, a cut-off journal
ending, or the whole directory rolled back to an older consistent copy cannot be detected without a vault-held
generation counter (not built yet). A torn final journal or in-flight record from a crash is ignored; damage to a
complete record is reported. An interactive scan may replace unreadable inventory and monitor state
after confirmation, keeping plans, journal and in-flight records. It refuses before replacing anything
if the existing audit history cannot be authenticated with the selected vault.

**The CLI to the network.** All outbound requests use the injected `HttpClient`; production adds a
host allow-list and a network receipt. HTTPS, URL validation, redirect checks, response-size limits,
and time limits constrain where requests go and how much data is accepted. The receipt records
host, purpose, method, time, and status, never authentication headers or bodies. A permitted host
can still return false or malicious data. The allow-list does not constrain unrelated processes.

Notification webhook URLs and topics can themselves be credentials. The local setup stores them in the vault,
adds exact configured HTTP destinations as user rules/trusted URLs, and never records URL paths in the receipt.
Health-check hosts require explicit user rules. SMTP is an explicit non-HTTP exception: it uses TLS or mandatory
STARTTLS with certificate checks and writes one `smtp:<host>` metadata entry to the receipt.

**The CLI to the operating system.** The optional Node permission model limits file access and
child-process use on supported patched versions. On Node 22 it is enabled only at **22.23.4 or
later**. Node 22 has no network permission flag; the client allow-list remains the network control.
The helper allowance needed for OS vaults is not a separate sandbox for those helpers. Node's
permission model does not protect against malicious code; see [Node's documented limits](https://nodejs.org/docs/latest-v22.x/api/permissions.html)
and the [recorded version facts](../notes/phase1-facts.md#4-nodejs-permission-model-versions).
Inside the permission model Node refuses `fsync`, so keysentry's writes are atomic (temporary file and
rename) but not forced to disk: they survive a keysentry crash, and a power loss within seconds of a
rotation can lose the newest value. Recovery then reports a possible leftover key and revokes nothing;
`keysentry doctor` states this when the sandbox is on.

**A rotation across providers and consumers.** Dry-run is the default. A replacement is stored in
the encrypted in-flight store before host writes; an old readable value is retained there when
undo needs it. The journal supports resuming known work after an interruption. The engine verifies
the replacement and checks deployment outcomes before normal revocation. A grace period can keep
the old key available for undo. When the plan no longer needs stored values, deleting the
per-rotation vault key makes those records unreadable, then the records are removed.

This cannot make separate providers transactional. A crash just after key creation and before the
encrypted value is stored can leave an orphan suspect; it is reported and nothing is revoked by
guesswork. A write-only old value cannot be restored. A platform that applies values on the next
deployment needs an explicit activation decision. Cloudflare's atomic roll invalidates the old
token immediately and cannot provide overlap or restore it.

**Feeds to automatic authorization.** News and official feeds are untrusted input. Size caps, defensive XML parsing,
sanitized text, per-source platform rules and publisher-owner corroboration reduce accidental triggers. The first
successful content read establishes a silent baseline. Later evidence must be unseen; dated items must fall within
72 hours and cannot be future-dated. A single news report raises an alert and approval request; news without
credential-exposure evidence never rotates. Official reports also require credential exposure in the platform's
own systems, excluding denials, instructional titles and third-party package or Action compromises.
A high-confidence official advisory or the defined corroborated evidence can trigger only inside a valid,
unexpired device-signed plan. This is not proof that the reporting source is truthful. Compromise of an official
feed, or collusion between sources counted as independent, can still supply misleading eligible evidence.

Current inventory is checked against every armed consumer. New/removed consumers, changed fingerprints and scope
growth request approval. Any scan error holds automatic rotation and deferred revocation. Autopilot excludes payment, database, encryption, wallet/private keys, atomic rolls,
guided methods and generated secrets outside the exact-name allow-list. Write-only adoption is a supervised real
rotation that records a fingerprint and provider reference; watcher adoption updates need a locally re-signed
plan. Deferred settlement uses a fresh read-role scan. Hosts can still omit a consumer or lie about deployment.

**Watcher to applications.** One wave per incident, a default 30-day host cooldown for follow-up reports, serial deployments, replacement verification, application
health checks, grace and a wave-wide revocation hold limit cascading changes. Signature/time/scope checks repeat
at automatic boundaries. Failure stops the wave; revocations already attempted during an interrupted settlement
cannot be undone atomically. Next-deploy revocation needs signed maximum-deadline acceptance; early activation
detection is not implemented. Disarm and `KEYSENTRY_ALERT_ONLY=1` stop automatic effects and settlement, without
restoring keys already revoked. Relay disarm signatures bind the trusted device, target watcher and timestamp;
verified disarms do not expire by age. The watcher polls before and between automatic effects, including during
recovery. This cannot interrupt an already running HTTP request. A remote disarm may be delayed by its transport.

The watcher falls back to alert-only when its external-notification window, state writability, armed-plan validity
or clock checks fail. Console output does not satisfy the notification window and hosted configurations exclude
console channels. Delivery means an external channel accepted the message, not that a person read it. An attacker
who controls the channel can suppress alerts after acceptance. Scheduled Actions can be delayed or skipped, and
encrypted cached state can be evicted or rolled back. Missing Actions state, including a first run, starts paused;
`keysentry autopilot resume --relay` publishes a trusted, watcher-bound, single-use recovery message. Resume clears
only the missing-state hold, preserving explicit disarm and signed scope. Authenticated sequence numbers reject
lower or missing records after a newer sequence has been observed in the process. Restoring an entire older cache
across runs cannot be detected by that cache alone; it requires a separately retained newer sequence. There is no
independent remote sequence anchor. One writer per state directory is required; there is no distributed lock.

**Messages and approvals.** Notification signatures bind the full message to a locally trusted device/watcher
public key. The short code is a lookup/check aid, not an approval credential. Notifications contain no secret
values and hints are opt-in; operators may still learn names, counts and timing. Text-channel truncation can
hide context, so signature verification requires the complete signed object. A valid signature proves the
signer, not that the proposed action is safe.

Passkey approvals bind exact action ID and digest to a random single-use challenge and require user verification.
Requests expire after ten minutes by default, or 60 minutes for Actions deployments. The digest binds the actual
planned keys, consumers and steps. Device approvals also bind the digest and time. Trusted keys, replay tracking and freshness protect
relay messages; relay topic secrecy is not authorization. Adding coverage, channels or credentials requires the
local human CLI and cannot be done through the relay. Relay approval verifies the watcher-signed request and asks
for confirmation after showing the keys and available hints. The watcher executes service-approved grants on its
next check through the same scan, eligibility, deployment and revocation rails; local `approve` uses that executor
directly. A grant remains available while execution is held, and only a durably completed or grace-pending action
is marked executed. Guided changes still need a person. Disarming requires no passkey. The approval server exposes
only bounded health/approval/disarm routes with exact Host/Origin checks, strict CSP and rate limits. Deployment
must correctly terminate TLS and configure proxy trust.

Local registration binds to loopback, uses a one-time token, opens as localhost, checks Host/Origin, serves only a
static script and closes after success or timeout. A localhost passkey is not a public-origin passkey. The server
does not provide public `/register`; the dashboard never enrolls passkeys, so public-origin enrollment
remains unavailable here. Notifications carry an approval-page URL only when a passkey for the watcher's public
origin is registered; otherwise they direct the user to the local approval command. Browser/authenticator
implementation, the selected origin and the local supervised enrollment remain trust boundaries.

**Watcher to its host.** The sealed config and encrypted state protect data at rest without their separately
supplied keys; the running host has both keys and process access. The image runs non-root with a read-only root
and a private writable volume; POSIX state directories with group/other permissions are refused. A host operator
or compromised host can still read memory, steal injected secrets, alter the running code or roll back files.
Setup exports only credentials needed by enabled hosts and armed providers, asks separately before including each
environment-sourced credential, and prints the exported names. The watcher excludes its operating credentials from
automatic rotation and names them for local changes when its own platform has an incident. It still rotates or
requests approval for the other covered keys. Hosting the watcher on a different platform can reduce shared exposure, but does not
remove either host's trust boundary.

**The audit log to the vault.** Entries form a SHA-256 chain, and each entry carries an HMAC-SHA256
over its hash using the 32-byte `audit/mac` key held in the vault. Missing or incorrect MACs are
reported at the first affected entry, so fabricating an append requires that vault key. Periodic
Ed25519 checkpoints and the vault-held known head detect replacement or tail truncation through the
latest saved checkpoint. `audit verify` always opens the selected vault and reads the head for the
log path; it refuses a nonempty log with no vault anchor. A public marker cannot skip that lookup.
Checkpoints are local, not an independent witness. Deleting a suffix after the latest saved head
remains undetectable until a newer head is saved. An actor able to replace the log and its vault-held
MAC key, signing key, and head can create a new consistent history. The audit log is tamper-evident
within that boundary, not tamper-proof.

Environment vaults keep the audit head in memory only. Their MAC key is also process-local unless the
same 32 UTF-8 bytes are supplied in `KEYSENTRY_VAULT_AUDIT_MAC`. A later audit inspection refuses a
nonempty log without a vault head; a valid checkpoint signature alone does not establish completeness.

**Source to release to installation.** Locked dependencies, installs with `--ignore-scripts`, a
readable bundle, a package without dependencies or install hooks, pinned workflow actions, and
least-privilege jobs reduce the paths by which other code enters a release. Rebuilding under two
locales/time zones and comparing every hash checks repeatability. A signature binds exact checksum
bytes to a trusted release key; provenance records a build's origin. These checks do not prove that
the source or build toolchain is safe.

Phase 1 has **no configured release public key**, so online signature verification is
`unconfigured` until a reviewed trust-list update. The local manifest checks bundle bytes against
an adjacent file, not against an independent authority. The phase-1 verifier does not verify npm or
GitHub provenance. Public attestation, release upload, and npm publishing jobs are gated off while
the repository is private. Public publishing, independent reproducibility, and signing-key
operations still need maintainer validation before a release.

## Actors and remaining risks

| Actor | What they could try | Response and residual risk |
|---|---|---|
| Network attacker | Read or alter API traffic, redirect it, or supply oversized responses. | HTTPS certificate checks, validated destinations, guarded redirects, and body/time limits. DNS, TLS trust roots, and the destination service remain trusted. Availability failures can still stop a scan or rotation. |
| Malicious package or build tool | Read credentials or change released code. | Locked source dependencies, ignored install scripts, bundled releases with no install hooks/dependencies, reviewable code, and reproducibility checks. A bundled malicious dependency still runs with the CLI's effective access; a compromised toolchain can produce consistently bad output. |
| Breached hosting platform | Read values it already hosts, lie about state, or undo an update. | Scope credentials narrowly, track every known consumer, verify and revoke in order. A platform can expose keys it holds and fake a successful deployment; keysentry cannot repair that trust boundary. |
| Breached notification channel | Read, suppress, alter or replay alerts; lure the user into taking action. | Signed watcher messages contain no values, hints are opt-in, and trusted-key verification detects edits. A message grants no approval. The operator can suppress delivery or retain metadata; legacy monitor webhook messages do not gain signature guarantees merely by using the same channel. |
| News feed author | Publish a misleading story, replay an old item or abuse a platform mention to provoke changes. | Bounded parsing, first-read baselines, freshness checks, platform-subject exposure rules, publisher-owner corroboration and incident cooldowns limit triggers. Uncorroborated news alerts; automatic rotation requires signed-plan scope. Incorrect official evidence or colluding independent owners remain possible. |
| Relay operator | Read metadata, inject messages, replay approvals, delay or suppress disarm. | Trusted-device signatures, exact action digests, freshness and single-use approval state reject forged or replayed authorization. The operator still controls availability and can observe topic/timing metadata. A public ntfy topic is not confidential. |
| Watcher host | Read runtime memory or injected keys, modify code, roll back state or interrupt work. | Sealed configuration, separately supplied state/vault keys, scoped credential export, private volume permissions and a non-root read-only image reduce filesystem exposure. The host remains trusted with running plaintext and can defeat these controls. Own-platform incidents continue other covered rotations and request local changes for operating credentials. |
| Same-user malware | Ask the OS vault for entries, read process memory or environment values, or replace files. | OS storage and encryption reduce exposure from files alone. They do not isolate keysentry from another process with your user's privileges in an unlocked session. |
| AI coding agent or agent-driven browser | Invoke mutation commands, click dashboard controls or obtain keys indirectly through local tools. | No product MCP/agent interface, interactive CLI mutation checks, marker-triggered read-only dashboard, terminal-only passkey enrollment, exact-action user-verified passkeys, and value-free normal output. An agent with unrestricted same-user file/process access can bypass keysentry and its markers; OS and tool permissions must enforce that separate boundary. |
| Foreign web page or local process | Rebind a hostname, make cross-origin requests, steal a sign-in link or replay a dashboard action. | Loopback binding, exact Host/Origin, single-use expiring link, strict session cookie/CSRF checks, CSP and fresh route/body-bound passkey proofs constrain access. A stolen unused link can establish a session; same-user process/browser compromise is outside those controls. |
| Recipient of a share card or timeline | Infer infrastructure, counts or incident timing from an export. | Card platform/counts are opt-in and names/hints/values never enter it; timelines escape and redact recorded events. Chosen metadata can still identify a deployment or event, and publication is irreversible from keysentry. |
| keysentry maintainers | Ship an unsafe implementation or change the release trust list. | Open source, readable release code, explicit trust roots, release signatures, checksums, provenance workflows, and independent rebuilding enable review. Maintainers still control releases; a valid signature identifies the signer, not the safety of the code. There is no external audit yet. |

## What keysentry does not protect against

- **Same-user malware in an unlocked session**, including an unrestricted coding agent that can
  access the same vault, files, environment, or process memory through other tools.
- **A compromised operating system**, credential-store service, administrator account, runtime,
  or build toolchain.
- **A breached provider issuing the new key** or a host that already receives it. Rotation can
  replace a value; it cannot make that provider trustworthy.
- A consumer keysentry did not discover, copied credentials outside the chosen scope, or a value
  that was exposed before revocation. A partial scan is not proof that every copy was found.
- Guaranteed application correctness or continuous availability during a rotation. API success and
  key verification do not replace application-specific health checks.
- Complete erasure from immutable backups, snapshots, swap, crash dumps, or JavaScript memory.
  Deleting a current vault key cannot delete an earlier independent copy of that key.
- Tamper evidence if the same actor controls both local audit files and their vault-held trust
  material, or authenticity based only on a local bundle and local manifest that changed together.

## Later phases

The trust design also describes public-origin passkey enrollment, confidential cloud boxes,
and team/enterprise roles. Those remain later work, not protections established by the local dashboard. No cloud box or control plane is
deployed here, and there is no current claim that confidential hardware prevents operators or a
cloud provider from accessing a running keysentry instance. Legacy monitor policy remains distinct from the
signed armed-plan scope; enabling one does not authorize the other.

Before public release, the maintainer must finish integration review, exercise real OS vaults,
run the release and reproducibility builds outside the sandbox, validate install/verify behaviour,
and assess the remaining issues in an independent review. Live adapter tests require separate
staging accounts and remain unverified until those tests are performed.
