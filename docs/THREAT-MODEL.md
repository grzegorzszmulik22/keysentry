# keysentry 1.0 threat model

keysentry needs access to secret values to compare their copies and replace them. This is a local
CLI, loopback dashboard and optional watcher that you host. You choose the projects and credentials they can
use. Its [trust promise](GUIDE.md#the-trust-promise)
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

**Proxy, extra CA and offline mode (phase 5).** With `network.proxy` (or `HTTPS_PROXY`) every request is tunnelled
through HTTP CONNECT and TLS still runs end to end, with the destination name verified, so the proxy learns host
names and timing but not request content. A TLS-inspecting proxy only works if you add its CA, and then it can read
and alter everything, including tokens: treat adding a CA as trusting that party with all keysentry traffic.
`network.caFile` adds certificates to Node's default roots for every host keysentry contacts; it never replaces them
and refuses files that contain anything but certificates. Node's defaults are its bundled Mozilla list plus the
certificates in `NODE_EXTRA_CA_CERTS`, and the operating system's store only when Node runs with `--use-system-ca`;
whoever controls the environment controls those too. `NODE_TLS_REJECT_UNAUTHORIZED=0` would turn certificate checks
off for Node's own fetch, so keysentry then uses its own transport, which keeps them on, and doctor warns. Proxy
credentials come from the vault (`KEYSENTRY_PROXY_AUTH`) or `HTTPS_PROXY`, are sent only on the CONNECT request, and
cross the LAN unencrypted to an `http://` proxy. A broken proxy, CA or policy setting refuses every request instead of
silently going direct; syslog export, which cannot be tunnelled, makes the same proxy decision and refuses a host the
proxy covers. A deployed watcher receives the CA certificates themselves and, with `network.proxy`, the proxy
credential inside its encrypted deployment vault (an environment value only with consent); its `/healthz` reports 503
when its own settings refuse every request, and after three connection attempts in a row to its proxy failed. Offline mode stops feed and news polling and removes their hosts from the
allow-list; it trades early breach warning for fewer outbound contacts, and an autopilot wave can then never start.

**Self-hosted servers (phase 5 and 6).** Coolify, the Kubernetes API server, Vault and a self-hosted Infisical are
reached at exactly the host and explicit port you configured; rules without a port allow only 443, built-in rules
never carry a port, and IP literals are refused everywhere, so such a server needs a DNS name. These servers, like
any configured destination, are trusted to answer honestly; a compromised self-hosted server can see the values
keysentry writes to it and fake a successful write. Secret stores do not deploy: unless you declare that consumers
read at use time (`activation: immediate`), activation stays unconfirmed and the old key is retained until you
finish. On-write hosts (Heroku, DigitalOcean, Cloudflare Workers) deploy with every write, including writes a
grace-period undo makes, so `--no-redeploy` cannot stage a change there. Kubernetes Secrets that a controller manages
(an owner reference or a secret-controller marker) and TLS Secrets are read but never written: a controller would
restore the old value. Reading them lets a rotation see every copy of a key, so a key also held there is never rolled
and its old key is never revoked automatically; the user updates the controller's source and revokes it.

**Customer KMS for the state key (phase 5).** With a `kms` section the state key is stored only wrapped, bound to
the project (encryption context, AAD or a context hash), and unwrapped into memory at start through a client that
reaches only the KMS hosts. Whoever controls the KMS key and its credentials can unwrap the state key, and can also
make saved state permanently unreadable by disabling or deleting the key; keysentry refuses to start rather than
create a new key. The KMS credentials stay outside `CREDENTIAL_NAMES`, and loadConfig does not read them. The watcher
deployment exports a KMS credential only where the same name is also a host credential: `VAULT_TOKEN` is the vault-kv
host's token too, and it is exported when that host is enabled and configured. Supply the other KMS credentials to a
watcher separately. Two processes that start a new project together create one wrapped key between them (a lock file
in `.keysentry/` and a re-read after taking it), so neither encrypts state with a key the vault no longer holds. The
lock works like the saved state lock: it waits through Windows "delete pending" lock files, and a lock left by a
process that stopped is never taken over automatically (two waiters could each remove the other's fresh lock); the
start stops and says which file to remove once no keysentry command is running.

The binding is authenticated where the KMS authenticates it: an AWS encryption context, Google AAD and Vault Transit
`context` or `associated_data` all need encrypt permission on your key to produce a record that unwraps. Vault Transit
answers 200 when it ignores a parameter, so keysentry refuses a response that warns about it and checks once per
process that decrypting with another context fails. Azure Key Vault is different: it wraps with RSA-OAEP, which is
public-key encryption, and has no additional authenticated data. keysentry binds the context by wrapping
`sha256(context) || key` and checking that prefix after unwrapping, which stops honest records being reused for
another project or key, but it is not authentication: anyone who has the key's RSA public key (readable with
`keys/get`, and not secret) and write access to the keysentry vault can build a wrapped record for a data key of their
choice. keysentry would then unwrap and use that key for state it writes from then on (state already written under
the real key does not open with it, so a planted key shows up as locked saved state). With Azure, the vault's own
protection (an OS keychain or the encrypted file) is therefore what keeps the state key yours; use AWS KMS, Google
Cloud KMS or Vault Transit when that is not enough. `kms rotate` rewraps this computer's record only; a deployed
watcher's `KEYSENTRY_STATE_KEY_WRAPPED` stays under the key version current at watcher setup.

**Audit export (phase 5).** Exported records are value-free metadata from the verified prefix of the audit chain,
and each entry's MAC is checked again on the bytes read for sending, so a file swapped between the verification and
the read is refused rather than exported. Each HTTPS target gets a single-host client that follows no redirect, syslog
connects only to the configured host:port over TLS, and webhook batches are signed: by this computer's device key, or
by a deployed watcher's own key for the batches it sends; `audit export status` lists every such public key. S3
object names carry the source and log identity, so a recreated log cannot overwrite or block an earlier log's
objects. A receiver or anyone on its path learns event kinds, timing and names such as variable names. Duplicates are
possible after a crash; gaps are not. Syslog has no acknowledgement, so a batch is counted when every byte left this
computer, and a server that does not close the session gets an "unconfirmed" note.

**The CLI to the operating system.** The optional Node permission model limits file access and
child-process use on supported patched versions. On Node 22 it is enabled only at **22.23.4 or
later**. Node 22 has no network permission flag; the client allow-list remains the network control.
The helper allowance needed for OS vaults is not a separate sandbox for those helpers. Node's
permission model does not protect against malicious code; see [Node's documented limits](https://nodejs.org/docs/latest-v22.x/api/permissions.html).
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
does not provide public `/register`; the local dashboard never enrolls passkeys, so public-origin enrollment for the
watcher remains unavailable here (the team dashboard's `/enroll` creates inert candidates only, see
[Teams, policy and single sign-on](#teams-policy-and-single-sign-on)). Notifications carry an approval-page URL only when a passkey for the watcher's public
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

## Teams, policy and single sign-on

**The roster is the only source of team trust.** Members, roles, device keys, passkeys and pinned single sign-on
identities live in one signed roster. Each version links to the previous one by hash and needs distinct admin
signatures (Ed25519 device keys) from admins of the previous version: the previous version's admin threshold, or the
applied policy's `approvals.wideningAdmins` when that is higher. A removed admin cannot sign the next version; a new
admin cannot vote for their own addition; lowering the threshold still needs the old threshold; a change that would
leave fewer admins with device keys than `wideningAdmins` is refused. Signatures must use the canonical base64
spelling, so one document has one hash, and two members cannot list the same passkey public key. The applied version
is kept in encrypted state and its version and hash in the vault, so an older state file copied back, a forked version
or a deleted state file is refused rather than accepted ("rollback protection"). An environment-variable vault (CI)
cannot hold that copy: there the encrypted state file is the only record of the applied roster and policy, and
deleting it loses rollback protection on that computer.

**Trust on first use and fingerprints.** A computer with no roster cannot check a roster's signatures meaningfully:
whoever writes a roster chooses its admins. `team apply --fingerprint` makes the person compare a 128-bit prefix of the
roster hash with an admin over another channel; that comparison is the trust anchor. An attacker who controls both the
roster file and the channel used for the fingerprint can make a new computer join their own team. After the first
roster, every later version is verified against the one in use.

**Admin threshold and policy.** The first signed policy (policy-as-code) needs the roster's admin threshold of
signatures from current admins; every later version also needs the policy in force's `approvals.wideningAdmins`
admins, so the rules cannot be relaxed with fewer signatures than they require. A policy only narrows local
configuration. Under a policy the monitor's automatic actions (and their environment overrides) are off unless the
policy allows them, and then stay inside its hosts, providers and approval tiers; a minimum grace period also binds
"revoke immediately", "revoke now" at the grace prompt and `finish --now`. If the policy file, the roster or a policy
requirement cannot be verified, every change pauses with a specific message; nothing falls back to a weaker mode, and
turning team mode off under an applied roster pauses changes too. Narrowing that keysentry applies before it can read
state (the KMS unwrap of the state key at start-up) uses `keysentry.yaml` only. Inspection commands that open no state
(`keysentry network`, `keysentry verify`) apply the policy file's narrowing without checking its signatures, which can
only make them stricter.

**Quorum.** With a policy that needs N approvals, an action runs only after N distinct roster members with the needed
role approved it, each with their own roster passkey or device key, within the request's lifetime. The same credential
or member counts once; members removed or demoted before the action runs stop counting (approvals are checked again
when it runs); the requirement can only grow while a request is pending; a request that recorded a quorum is never
approved by a single approval because the roster stopped being visible. Members' own computers each hold their own
approval state: a quorum is collected where the request lives (the watcher, through the relay or its approval page, or
the team dashboard), not across separate computers.

**Team dashboard changes.** On the team dashboard every change that rotates, finishes, undoes, revokes, caps, arms,
dismisses, reveals, or changes settings, channels or vault entries is a team request bound to that exact change and
requester. The requester's passkey confirmation is their approval; the change runs only when the approval service
reports the quorum met (operators: `approvals.required` by risk tier; admin changes: `approvals.wideningAdmins`
admins, or the roster's threshold without a policy), and every runtime entry point it calls re-checks that approved
request against the current roster and policy before acting, so no route can skip it. Each approved request runs
once: it is claimed in the approvals file before it runs, under a cross-process lock like the saved state lock, so a
retry, another request handler or another process cannot run it again even when marking it executed later fails or
the run was interrupted. A dismissal carries the keys of the request it dismisses, so per-tier rules apply to it. An
arm request that adopts write-only keys names them and binds them into its digest; its approval covers exactly that
one rotation, and it needs the approvals rotating those keys needs as well as the arming admins. Request bodies that
carry a secret are never stored; the requester submits them again after approval. Reveals
and disarms are announced on the team's notification channels with the member's id, and every audit event a dashboard
request causes records that member (exports carry it as `actor`). Disarm needs the member's passkey but never a quorum
or governance check: it only reduces automation.

**The team dashboard's host.** `ui --team` refuses to start where the device key belongs to an admin, so the
internet-facing host never holds a key that signs roster or policy changes. It still holds the platform and provider
tokens the dashboard acts with, and anyone with a terminal on it can use them directly (the CLI there is outside the
dashboard's roles and quorum, like any member's own computer). A device key on the host that belongs to a non-admin
member lets such a person approve as that member; `ui --team` warns about it.

**Single sign-on is limited to reading and signing in.** The identity provider says who someone is; the roster says
what they may do. A provider session opens the team dashboard at the member's role for reading. Every change, and
disarm, needs that member's own passkey for the dashboard's host, listed in the signed roster; changes also need the
quorum; roster and policy changes need admins' device keys. A pinned member (`sso` in the roster) maps only from the
exact issuer and subject, so a reassigned email address cannot sign in as them; unpinned members map by verified
email compared in ASCII only (a non-ASCII address never matches), and OIDC Core §5.7 warns that email is not a stable
identifier, which is why pinning exists.

**Passkey enrollment for the public host.** A member's passkey for the team dashboard is created on `/enroll` from a
link an admin signs on their own computer with their device key: `{ member, origin, expiry, nonce }`, valid 15
minutes. The dashboard host checks the signature against the current roster's admins, the expiry and its own origin,
and keeps only a hash of each used nonce (single use); it needs no admin key. The link travels in the URL fragment. The
result is a pending public credential that grants nothing until an admin signs it into the roster on their own
computer (`team add-passkey <member> --card <file>`, from the card the host exports with `team passkeys pending -o`),
which refuses a candidate for any member other than the invited one; the host then applies the new roster like any
computer. Someone who intercepts a link before the member uses it can enroll their own authenticator as a candidate;
the admin's comparison of the candidate's fingerprint with the member is what stops it from reaching the roster. The
authenticator model a `none` attestation reports is the authenticator's own claim, not verified. Enrollment is
rate-limited, refuses reuse, does not exist on the local dashboard, and is the only page whose permissions policy
allows credential creation.

**Notification routing.** A channel a member received stays member-owned when no member receives it any more (the
roster lists it as retired), so removing a member never turns their personal channel into one that receives every
team message, approval links included. `team remove` and `team notify --clear` refuse while the member has such
channels unless `--drop-channels` removes them locally.

**Deployed watchers keep the sealed roster.** `watcher setup` seals the verified roster and policy into the watcher's
config. A deployed watcher or cloud box does not read later roster versions: a removed or demoted member keeps the
approvals and disarms they had there until `watcher setup` (or `box send-tokens`) runs again. `team remove` and
`team role` say so when a watcher or box is known.

## Cloud box

**Status.** The cloud box is built and tested against a local emulator. It is not launched: no box, control plane,
KMS key or allow-list entry exists in any cloud project, and nothing here has run on Confidential Space hardware.
The emulator signs tokens with local test keys; passing its checks says nothing about real hardware.

**The claim** (used verbatim in the CLI and README): "Your keys are decrypted only inside a confidential machine
running the exact open-source build you can verify. Our staff cannot log in to it and the cloud provider cannot read
its memory. In the standard option we control the key-release policy; every change to it is public. With
bring-your-own-KMS, only you control it."

**What the CLI checks before anything is sent.** The box makes fresh X25519 and Ed25519 keys at every boot and asks
the Confidential Space launcher for an attestation token whose nonces are a hash of both public keys and the CLI's
fresh challenge. The CLI verifies the RS256 signature against Google's published keys (or the certificate chain to
the pinned Confidential Space root), issuer, audience, time with 60 seconds of skew (the handshake allows the same skew
between the two machines), both nonces, secure boot,
`dbgstat == disabled-since-boot`, `swname == CONFIDENTIAL_SPACE`, TDX or SEV hardware, `STABLE` support, memory
monitoring off, no environment or command override, the project and service account, and the image digest. For the
hosted box the allowed digests are meant to come from the signed allow-list; this build checks that list only in
`keysentry box allowlist verify`, and the emulator uses its own test digests, so wiring the list into `box check` is a
launch requirement. It also checks that the attestation is signed by the key the box announced. The bundle is
encrypted to the attested key, bound to the session, and signed by the user's device key; the box acknowledges only
after sealing it at rest. Every exchange passes through the relay, which is untrusted: it can delay, drop or reorder
messages, but a substituted key or an old attestation fails a named check and no token is sent.

**What remains trusted.**

- Google's attestation service, its token signing keys and the Confidential Space root certificate. A forged token
  signed by those keys would pass every check.
- The Confidential Space launcher and image: launch-policy enforcement (no command or environment override, logs
  only on debug images, no memory monitoring), the token server, and the absence of operator login on production images.
- Intel TDX or AMD SEV hardware, firmware and their memory encryption. Side channels and hardware flaws are outside
  what keysentry can detect.
- Cloud KMS and STS enforcing the key-release condition (image digest, project and service account). In the standard
  option keysentry sets that condition; changes to the allowed digests are visible in the public allow-list, but a
  first-time client cannot detect a log that was rolled back as a whole (it keeps a checkpoint after its first check).
  With bring-your-own-KMS the customer sets it.
- The open-source box image itself: it is the same release bundle as the CLI, built reproducibly, and the allow-list
  should only ever list digests of reviewed releases.

**Known limits of this build.**

- The first device to enroll a box comes from routing outside the box (instance metadata in production). Whoever
  controls that routing can enroll a box to their own device, which gives them a box holding *their* tokens and
  denies service to the user; it cannot reveal the user's tokens, because the user's CLI encrypts only to a box that
  answers its own signed challenge. Later sessions use the device keys sealed inside the record.
- A complete, older sealed record of the same box can be restored by whoever controls its disk; there is no
  monotonic counter. The box would run the older deployment until new tokens are sent.
- In unlock-on-restart mode, notification settings for the one restart notice are sealed under KMS alone, so a
  locked box can still reach the user. Those channel secrets have the standard option's protection, not the device
  share's. The notice is signed by the box's per-boot key, which the user cannot check; it grants nothing and only
  asks the user to run `keysentry box unlock`, which verifies the box again. The "notice sent" flag on disk carries a
  MAC under a key derived from the sealed notice record, so writing that file alone cannot silence the notice; a disk
  owner can still delete records, which stops the box (it never re-enrolls over a record whose routing file vanished).
- Plaintext lives in the box process's memory while the watcher runs. Buffers the box owns are cleared; JavaScript
  strings cannot be, and garbage collection decides when they disappear.
- Unverified on real infrastructure: whether a non-root container user can reach the launcher socket, whether
  Node's permission model allows that Unix-socket connection, whether the container's state directory survives a
  VM restart, and how the relay authenticates a box (this build presents an attestation token for the relay's own
  origin; the control plane does not yet accept it).

## Actors and remaining risks

| Actor | What they could try | Response and residual risk |
|---|---|---|
| Network attacker | Read or alter API traffic, redirect it, or supply oversized responses. | HTTPS certificate checks, validated destinations, guarded redirects, and body/time limits. DNS, TLS trust roots, and the destination service remain trusted. Availability failures can still stop a scan or rotation. |
| Malicious package or build tool | Read credentials or change released code. | Locked source dependencies, ignored install scripts, bundled releases with no install hooks/dependencies, reviewable code, and reproducibility checks. A bundled malicious dependency still runs with the CLI's effective access; a compromised toolchain can produce consistently bad output. |
| Breached hosting platform | Read values it already hosts, lie about state, or undo an update. | Scope credentials narrowly, track every known consumer, verify and revoke in order. A platform can expose keys it holds and fake a successful deployment; keysentry cannot repair that trust boundary. The same holds for secret stores and self-hosted servers. |
| Proxy operator or added CA | Observe destinations and timing; with a CA you trusted, read or alter all traffic including tokens. | CONNECT tunnelling keeps end-to-end TLS when no extra CA is configured; a broken setting fails closed. A CA you add for TLS inspection is fully trusted. |
| KMS operator | Unwrap the state key, or disable or delete the KMS key. | Context binding stops a wrapped key being reused for another project; a KMS failure refuses to start. Disabling the key makes saved state unreadable by design. With Azure Key Vault the binding is an unauthenticated hash prefix, so vault write access plus the key's public key is enough to plant a known state key for new state. |
| Breached notification channel | Read, suppress, alter or replay alerts; lure the user into taking action. | Signed watcher messages contain no values, hints are opt-in, and trusted-key verification detects edits. A message grants no approval. The operator can suppress delivery or retain metadata; legacy monitor webhook messages do not gain signature guarantees merely by using the same channel. |
| News feed author | Publish a misleading story, replay an old item or abuse a platform mention to provoke changes. | Bounded parsing, first-read baselines, freshness checks, platform-subject exposure rules, publisher-owner corroboration and incident cooldowns limit triggers. Uncorroborated news alerts; automatic rotation requires signed-plan scope. Incorrect official evidence or colluding independent owners remain possible. |
| Relay operator | Read metadata, inject messages, replay approvals, delay or suppress disarm. | Trusted-device signatures, exact action digests, freshness and single-use approval state reject forged or replayed authorization. The operator still controls availability and can observe topic/timing metadata. A public ntfy topic is not confidential. |
| Watcher host | Read runtime memory or injected keys, modify code, roll back state or interrupt work. | Sealed configuration, separately supplied state/vault keys, scoped credential export, private volume permissions and a non-root read-only image reduce filesystem exposure. The host remains trusted with running plaintext and can defeat these controls. Own-platform incidents continue other covered rotations and request local changes for operating credentials. |
| Same-user malware | Ask the OS vault for entries, read process memory or environment values, or replace files. | OS storage and encryption reduce exposure from files alone. They do not isolate keysentry from another process with your user's privileges in an unlocked session. |
| AI coding agent or agent-driven browser | Invoke mutation commands, click dashboard controls or obtain keys indirectly through local tools. | No product MCP/agent interface, interactive CLI mutation checks, marker-triggered read-only dashboard, terminal-only local passkey enrollment (team passkeys reach the roster only through admins' signed changes), exact-action user-verified passkeys, and value-free normal output. An agent with unrestricted same-user file/process access can bypass keysentry and its markers; OS and tool permissions must enforce that separate boundary. |
| Foreign web page or local process | Rebind a hostname, make cross-origin requests, steal a sign-in link or replay a dashboard action. | Loopback binding, exact Host/Origin, single-use expiring link, strict session cookie/CSRF checks, CSP and fresh route/body-bound passkey proofs constrain access. A stolen unused link can establish a session; same-user process/browser compromise is outside those controls. |
| Recipient of a share card or timeline | Infer infrastructure, counts or incident timing from an export. | Card platform/counts are opt-in and names/hints/values never enter it; timelines escape and redact recorded events. Chosen metadata can still identify a deployment or event, and publication is irreversible from keysentry. |
| Identity provider (team dashboard) | Sign someone in as a member, reassign an email address, or deny sign-in. | The provider can grant reading at a member's role. Changes and disarm need the member's roster passkey, and changes also the team's quorum; roster and policy changes need admins' device keys. Pinned members accept only their exact issuer and subject; email matching folds ASCII case only. It can deny service to every member. |
| Team member | Approve alone, approve twice, act above their role, or keep acting after removal. | Quorum counts distinct members once each, team dashboard changes are requests that run only under the quorum, viewers cannot approve, operators cannot sign roster or policy changes, widening approvals need admins, and team dashboard sessions, requests and approvals re-check the current roster (approvals again when the action runs). A deployed watcher or cloud box keeps the roster sealed at setup until setup runs again. A member's own host tokens on their own computer stay outside roles; the policy still narrows them there. |
| Admin, or admins up to the threshold | Change the roster or policy, add an authenticator, lower the threshold. | That is their authority by design; changes are signed, versioned and audited, and joining computers check fingerprints. Fewer admins than the threshold, or than the policy's `wideningAdmins`, cannot make a valid roster or policy change. With one required signature, one admin can add a member whose key they hold; `team add` warns when the policy needs more approvers than that. |
| Loss of an admin device | Freeze the team: with no spare admin, no later roster or policy change can be signed. | Signing and applying a roster or policy that leaves no spare signing admin (a single admin, or 2-of-2 widening) warns plainly. There is deliberately no bypass, reset or recovery key: anything that could sign for a lost device could also take over the team. Recovery is a spare admin with a device key on another computer, added before it is needed. |
| Team dashboard host | Use the platform tokens in its vault, or approve as a member whose device key it holds. | It never holds an admin's key (`ui --team` refuses), so it cannot sign roster or policy changes. Anyone with a terminal there can use its tokens outside the dashboard's roles and quorum; protect it like the tokens. |
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

Team roles, quorum, signed policy, single sign-on and public-host passkey enrollment are built and tested against
fakes (see [Teams, policy and single sign-on](#teams-policy-and-single-sign-on)); no real identity provider or browser
has been used with them yet. The cloud box is built but
not launched (see [Cloud box](#cloud-box)): no cloud box or control plane is deployed, so no running
keysentry instance is protected by confidential hardware today. Legacy monitor policy remains distinct from the
signed armed-plan scope; enabling one does not authorize the other.

Before public release, the maintainer must finish integration review, exercise real OS vaults,
run the release and reproducibility builds outside the sandbox, validate install/verify behaviour,
and assess the remaining issues in an independent review. Live adapter tests require separate
staging accounts and remain unverified until those tests are performed.
