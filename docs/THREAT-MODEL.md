# keysentry phase 1 threat model

keysentry needs access to secret values to compare their copies and replace them. This is a local
CLI, not a service that takes custody of your keys. You choose the projects and credentials it can
use. Its [trust promise](superpowers/specs/2026-10-27-trust-autopilot-design.md#3-the-trust-promise)
guides the design; the [access guide](ACCESS.md) describes the actual integration permissions.

This model covers 1.0 phase 1: vault storage, encrypted state, network restrictions, an audit log,
rotation recovery, human confirmation, and release tooling. There has been **no external security
audit**. Adapter behaviour has **not yet been tested against live accounts**. Fake API tests and
source review can check our decisions and formats, but cannot establish every provider's live
permission or deployment behaviour.

## Assets

| Asset | Why it matters | Where phase 1 permits it |
|---|---|---|
| Hosting and provider credentials | Can reveal configuration, create or disable keys, or deploy code within their scopes. | OS vault, explicitly chosen encrypted-file vault, or a supported environment source; plaintext while needed in memory and in authorized API headers/bodies. |
| Existing and replacement secret values | Applications need them; losing a replacement can interrupt a rotation. | Original host/provider, process memory, and encrypted per-rotation records while recovery or undo needs them. |
| State and fingerprint keys | Allow saved inventory to be decrypted and copies of a value to be matched. | Vault; in memory while used. |
| Inventory, plans, journal, hints, service names | Describe infrastructure even without full secret values. | Encrypted project state. Exported reports and terminal output need the user's own care. |
| Audit chain, MAC key and device signing key | Help detect changes to the recorded history. | Secret-free audit metadata in a local log; MAC key, signing key and known head in the vault. |
| Release signing key and trusted public keys | Determine which published checksum signatures users accept. | Private key in the maintainer's release secret store/signing process; public trust list in the source and bundle. |
| Running applications | A mistimed change or revocation can stop them. | Hosting platforms controlled by the user; modified only through an approved rotation. |

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

| Actor | What they could try | Phase-1 response and residual risk |
|---|---|---|
| Network attacker | Read or alter API traffic, redirect it, or supply oversized responses. | HTTPS certificate checks, validated destinations, guarded redirects, and body/time limits. DNS, TLS trust roots, and the destination service remain trusted. Availability failures can still stop a scan or rotation. |
| Malicious package or build tool | Read credentials or change released code. | Locked source dependencies, ignored install scripts, bundled releases with no install hooks/dependencies, reviewable code, and reproducibility checks. A bundled malicious dependency still runs with the CLI's effective access; a compromised toolchain can produce consistently bad output. |
| Breached hosting platform | Read values it already hosts, lie about state, or undo an update. | Scope credentials narrowly, track every known consumer, verify and revoke in order. A platform can expose keys it holds and fake a successful deployment; keysentry cannot repair that trust boundary. |
| Breached notification channel | Read, suppress, or alter alerts; lure the user into taking action. | Notification content must contain no secret values. A message alone grants no CLI approval. Phase 1 does not implement the later signed-message and passkey-approval system; verify the proposed action in your own terminal. Delivery and authenticity of existing webhook notifications are not guaranteed. |
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

The trust design also describes armed breach autopilot, a managed watcher, signed notifications,
passkey approvals, a local dashboard, confidential cloud boxes, and team/enterprise roles. Those
are later phases, not protections established by this work. No cloud box or control plane is
deployed here, and there is no current claim that confidential hardware prevents operators or a
cloud provider from accessing a running keysentry instance. An existing monitor policy is not the
later signed armed-plan and passkey approval system.

Before public release, the maintainer must finish integration review, exercise real OS vaults,
run the release and reproducibility builds outside the sandbox, validate install/verify behaviour,
and assess the remaining issues in an independent review. Live adapter tests require separate
staging accounts and remain unverified until those tests are performed.
