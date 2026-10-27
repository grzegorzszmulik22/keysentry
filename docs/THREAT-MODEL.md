# keysentry 1.0 threat model

keysentry needs access to secret values to compare their copies and replace them. This is a local
CLI and optional watcher that you host. You choose the projects and credentials they can
use. Its [trust promise](superpowers/specs/2026-10-27-trust-autopilot-design.md#3-the-trust-promise)
guides the design; the [access guide](ACCESS.md) describes the actual integration permissions.

This model covers 1.0 phases 1 and 2: vault storage, encrypted state, network restrictions, an audit log,
rotation recovery, human confirmation, release tooling, signed breach autopilot, notifications, approvals and
the self-hosted watcher. There has been **no external security
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

## Boundaries and controls

**Your terminal to the CLI.** Mutation requires the interactive human path. Known coding-agent
markers are refused even if a TTY is present. Read-only commands can be run by an agent at your
request and return metadata, not values. There is no MCP server or agent skill in the phase-1
product. Environment marker detection is an extra check; it is not an identity proof or an OS
access boundary.

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
sanitized text, per-source platform rules and publisher-owner corroboration reduce accidental triggers. A single
news report raises an alert and approval request; news without credential-exposure evidence never rotates.
A high-confidence official advisory or the defined corroborated evidence can trigger only inside a valid,
unexpired device-signed plan. This is not proof that the reporting source is truthful. Compromise of an official
feed, or collusion between sources counted as independent, can still supply misleading eligible evidence.

Current inventory is checked against every armed consumer. New/removed consumers, changed fingerprints and scope
growth request approval. Autopilot excludes payment, database, encryption, wallet/private keys, atomic rolls,
guided methods and generated secrets outside the exact-name allow-list. Write-only adoption is a supervised real
rotation that records a fingerprint and provider reference; watcher adoption updates need a locally re-signed
plan. Deferred settlement uses a fresh read-role scan. Hosts can still omit a consumer or lie about deployment.

**Watcher to applications.** One wave per incident, serial deployments, replacement verification, application
health checks, grace and a wave-wide revocation hold limit cascading changes. Signature/time/scope checks repeat
at automatic boundaries. Failure stops the wave; revocations already attempted during an interrupted settlement
cannot be undone atomically. Next-deploy revocation needs signed maximum-deadline acceptance; early activation
detection is not implemented. Disarm and `KEYSENTRY_ALERT_ONLY=1` stop automatic effects and settlement, without
restoring keys already revoked. A remote disarm may be delayed by its transport.

The watcher falls back to alert-only when its notification window, state writability, armed-plan validity or clock
checks fail. Delivery means a channel accepted the message, not that a person read it. An attacker who controls
the channel can suppress alerts after acceptance. Scheduled Actions can be delayed or skipped, and encrypted
cached state can be evicted or rolled back. One writer per state directory is required; there is no distributed
lock or rollback-resistant generation counter.

**Messages and approvals.** Notification signatures bind the full message to a locally trusted device/watcher
public key. The short code is a lookup/check aid, not an approval credential. Notifications contain no secret
values and hints are opt-in; operators may still learn names, counts and timing. Text-channel truncation can
hide context, so signature verification requires the complete signed object. A valid signature proves the
signer, not that the proposed action is safe.

Passkey approvals bind exact action ID and digest to a random, ten-minute, single-use challenge and require user
verification. Device approvals also bind the digest and time. Trusted keys, replay tracking and freshness protect
relay messages; relay topic secrecy is not authorization. Adding coverage, channels or credentials requires the
local human CLI and cannot be done through the relay. Disarming requires no passkey. The approval server exposes
only bounded health/approval/disarm routes with exact Host/Origin checks, strict CSP and rate limits. Deployment
must correctly terminate TLS and configure proxy trust.

Local registration binds to loopback, uses a one-time token, opens as localhost, checks Host/Origin, serves only a
static script and closes after success or timeout. A localhost passkey is not a public-origin passkey. The server
does not provide public `/register`; public enrollment remains a phase 3 dashboard feature. Browser/authenticator
implementation, the selected origin and the local supervised enrollment remain trust boundaries.

**Watcher to its host.** The sealed config and encrypted state protect data at rest without their separately
supplied keys; the running host has both keys and process access. The image runs non-root with a read-only root
and a private writable volume; POSIX state directories with group/other permissions are refused. A host operator
or compromised host can still read memory, steal injected secrets, alter the running code or roll back files.
The watcher excludes its operating credentials from automatic rotation and asks for guided changes when its own
platform has an incident. Hosting the watcher on a different platform can reduce shared exposure, but does not
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
| News feed author | Publish a misleading story, replay an old item or abuse a platform mention to provoke changes. | Bounded parsing, evidence classification, publisher-owner corroboration and incident deduplication limit triggers. News alone alerts; only signed-plan scope can execute. Incorrect official evidence or colluding independent owners remain possible. |
| Relay operator | Read metadata, inject messages, replay approvals, delay or suppress disarm. | Trusted-device signatures, exact action digests, freshness and single-use approval state reject forged or replayed authorization. The operator still controls availability and can observe topic/timing metadata. A public ntfy topic is not confidential. |
| Watcher host | Read runtime memory or injected keys, modify code, roll back state or interrupt work. | Sealed configuration, separately supplied state/vault keys, private volume permissions and a non-root read-only image reduce filesystem exposure. The host remains trusted with running plaintext and can defeat these controls. Own-platform incidents request guided credential rotation. |
| Same-user malware | Ask the OS vault for entries, read process memory or environment values, or replace files. | OS storage and encryption reduce exposure from files alone. They do not isolate keysentry from another process with your user's privileges in an unlocked session. |
| AI coding agent | Invoke mutation commands or obtain keys indirectly through local tools. | No product MCP/agent interface, interactive mutation checks, detected agent refusal, and value-free normal output. An agent with unrestricted same-user file/process access can bypass keysentry and its markers; OS and tool permissions must enforce that separate boundary. |
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

The trust design also describes a local dashboard, public-origin passkey enrollment, confidential cloud boxes,
and team/enterprise roles. Those are later phases, not protections established by this work. No cloud box or control plane is
deployed here, and there is no current claim that confidential hardware prevents operators or a
cloud provider from accessing a running keysentry instance. Legacy monitor policy remains distinct from the
signed armed-plan scope; enabling one does not authorize the other.

Before public release, the maintainer must finish integration review, exercise real OS vaults,
run the release and reproducibility builds outside the sandbox, validate install/verify behaviour,
and assess the remaining issues in an independent review. Live adapter tests require separate
staging accounts and remain unverified until those tests are performed.
