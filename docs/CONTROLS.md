# Controls mapping: SOC 2 and ISO/IEC 27001

This page is for security reviewers who need to place keysentry in their own control framework. It maps what
keysentry does to the AICPA Trust Services Criteria (2017, revised points of focus 2022) used in SOC 2 reports and to
the controls in ISO/IEC 27001:2022 Annex A, and names the evidence each feature produces.

Read it with three limits in mind:

- **keysentry is not certified** against either framework, and using it does not make you compliant. It is a tool
  that helps you operate some controls and gives you evidence for them. Your auditor decides whether that evidence
  meets your control objectives.
- **The mapping covers only what keysentry itself does.** Your identity provider, hosting platforms, providers,
  devices and processes carry most of each control.
- **Some features have been tested only against fakes** (see "Not verified yet" in `docs/BUILD-REPORT.md`): no adapter
  has run against a live account, and the cloud box and hosted control plane are not launched.

## Evidence you can collect

| Evidence | Command | What it shows |
|---|---|---|
| Tamper-evident audit log | `keysentry audit verify`, `keysentry audit export` | Every change keysentry made, hash-chained, MAC'd and checkpoint-signed; exported to your SIEM, OpenTelemetry collector, object storage or webhook with sequence numbers |
| Key inventory and blast radius | `keysentry scan`, `keysentry report --json` | Which keys exist, where they are deployed, which are shared, their risk tier |
| Key age and hygiene | `keysentry hygiene`, `keysentry digest` | First-seen dates, age, copies, rotation reminders, unused keys |
| Rotation records | `keysentry timeline <plan>`, `.keysentry/` reports | Detected, rotated, verified, revoked, with times; no values |
| Breach readiness | `keysentry drill` | A timed dry run with a 0–100 readiness score and what lowers it |
| Network destinations | `keysentry network` | Every permitted destination with its reason, and a host-only receipt of contacts |
| Local protections | `keysentry doctor` | Vault backend, sandbox, proxy/CA/offline state, token capabilities, team and policy status |
| Release integrity | `keysentry verify` | The installed copy against its manifest and, once keys are published, signed release checksums |
| Team and policy | `keysentry team list`, `team verify`, `policy show`, `policy verify` | Members, roles, the admin threshold, the signed policy and its version chain |
| KMS wrapping | `keysentry kms status` | Which KMS key protects the state key, and a live unwrap check |

## Mapping

| Area | What keysentry does | SOC 2 criteria | ISO 27001:2022 Annex A |
|---|---|---|---|
| Inventory of secrets | Finds keys in local files, git history and connected hosts; classifies provider and risk tier; maps every consumer | CC6.1, CC3.2 | 5.9 inventory of information and other assets, 5.12 classification |
| Least privilege for tokens | Separate read and write token roles; doctor explains what each token type can do and recommends the narrowest | CC6.1, CC6.3 | 5.15 access control, 5.18 access rights, 8.2 privileged access rights |
| No AI agent access | Mutating commands refuse agent environments and non-terminals; the dashboard needs a passkey for every change; no agent interface exists | CC6.1, CC6.8 | 5.15, 8.5 secure authentication |
| Authentication for changes | Passkeys bound to the exact action; device-signed approvals; N-of-M approvals by members with operator or admin roles | CC6.1, CC6.2, CC8.1 | 5.16 identity management, 5.17 authentication information, 8.5 |
| Team membership | A roster signed by a threshold of admins, chained by hash; removed admins cannot sign the next version; SSO subject pinning | CC6.2, CC6.3 | 5.16, 5.18 |
| Policy as code | A signed policy that only narrows: allowed hosts and providers, approvals per risk tier, offline mode, required proxy, rotation strictness, required audit export | CC5.2, CC8.1 | 5.1 policies for information security, 8.9 configuration management |
| Rotation and change control | Ordered plans, a preview before any write, grace periods, health checks, undo, crash-safe resume, revocation only after verification | CC8.1, CC7.4 | 8.32 change management, 5.26 response to incidents |
| Breach response | Official advisories and corroborated news trigger pre-approved rotations within the armed scope; news alone only alerts; kill switch | CC7.3, CC7.4, CC7.5 | 5.7 threat intelligence, 5.24–5.27 incident management |
| Monitoring | Spend and usage spikes, key exposure signals, a daily signed heartbeat, alert-only mode when notifications fail | CC7.2 | 8.16 monitoring activities |
| Logging | Tamper-evident audit log with signed checkpoints; export with sequence numbers for deduplication | CC7.2, CC4.1 | 8.15 logging, 5.28 collection of evidence, 5.33 protection of records |
| Cryptography | Encrypted state (AES-256-GCM), OS credential stores, optional KMS wrapping of the state key, signed notifications, sealed watcher configuration | CC6.1, CC6.7 | 8.24 use of cryptography |
| Network | HTTPS-only egress allow-list with reasons, redirect limits, no secrets in URLs, proxy and custom CA support, offline mode | CC6.6, CC6.7 | 8.20 networks security, 8.21 security of network services |
| Leak prevention | Pre-commit guard and history scan for committed keys; values never printed by default | CC6.1, C1.1 | 8.12 data leakage prevention |
| Supply chain | Readable bundle, no install scripts, pinned workflows, reproducible builds, signed checksums, Node permission sandbox | CC7.1, CC8.1 | 8.19 installation of software, 8.25 secure development life cycle, 8.30 outsourced development |
| Cloud services | Platform and provider adapters use documented APIs only; the cloud box verifies attestation before receiving tokens (not launched) | CC9.2 | 5.23 information security for use of cloud services |

## What keysentry does not cover

- Identity and device management for your people: joiner and leaver processes, MFA on your identity provider, device
  encryption and patching.
- The security of the platforms and providers that hold your keys, and of your application code.
- Backup and recovery of your applications' data. keysentry's own state can be restored only with its keys.
- Secrets outside the hosts and files you connect, and values exposed before rotation.
- Policies, training, risk assessments and vendor reviews, which your organisation owns.

See `docs/THREAT-MODEL.md` for what each control relies on and its remaining risks.
