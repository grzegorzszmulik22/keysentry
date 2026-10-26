---
name: keysentry
description: Use when responding to an exposed credential, assessing secret reuse across deployment hosts, planning key rotation, or setting up keysentry canaries and monitoring.
---

# keysentry breach response

Use the keysentry CLI or MCP server against the intended project and host scope. Keep application secrets, provider admin credentials, and webhook URLs in memory or their intended credential channel. Reports contain fingerprints and short hints.

1. **Scan:** run `keysentry scan` or MCP `scan`. Review disabled hosts, scan errors, sealed values, and account scope. Missing visibility is an unresolved gap.
2. **Assess blast radius:** run `keysentry report` or `blast_radius`. Identify duplicate clusters and all consumers. Wallet exposure requires moving funds to a new wallet first.
3. **Plan:** use `keysentry plan` or `plan_rotation`. Review tier order, all copies of shared secrets, required admin permissions, guided steps, atomic-roll downtime, and services needing manual activation.
4. **Dry run:** run `keysentry rotate` or MCP `rotate` without execution arguments. Show the human the selected clusters, service/variable diff, redeployments, revocation policy, and unresolved gaps. A dry run does not validate real writes or application recovery.
5. **Confirm and execute:** obtain explicit human confirmation for the reviewed scope before requesting execution. CLI: `keysentry rotate --plan <id> --execute`, with numeric confirmation. Use `--yes` only when that confirmation is already explicit. MCP: send both `execute: true` and `confirm: "ROTATE"` only after human confirmation. Never infer it from urgency, a scan request, or the MCP argument itself.
6. **Verify:** inspect every step and deployment, application health, and the journal path. Rescan. Investigate skipped/failed steps and retained old keys; do not claim completion from command success alone. Guided MCP steps return instructions; have the human complete them through a trusted hidden-input workflow.
7. **Prepare afterward:** with separate authorization for provider/host writes, plant canaries, review monitor policy, run `monitor --once`, and schedule monitoring and `drill`. Default monitoring can cap supported keys even when automatic rotations are disabled.

## Safety rules

- Never paste, print, persist, or include plaintext credentials in tool arguments, runbooks, chat, logs, URLs, or query strings. Do not pass replacement values as CLI flags. Use hidden input or intended provider/host interfaces.
- Dry-run first. Execute only the approved scope. Keep every known copy of a selected cluster in its plan; never replace a host's entire variable set or alter unrelated variables.
- Verify replacements before writes. Revoke old keys only after all consumers update and required deployments succeed. Cloudflare atomic rolls invalidate immediately; disclose that risk before confirmation.
- Fail closed on verification failure. Treat `unverified`, sealed secrets, null deployment IDs, and missing admin credentials as limits requiring review. Do not bypass them with immediate revocation.
- Unattended monitoring skips guided replacements. Keep cooldowns and daily rotation limits; review pending actions before `approve <id>`. Run one monitor per state directory.
- Preserve `.keysentry/` privacy and its stable fingerprint key. Inspect the journal before retrying a partial execution; v1 has no automatic rollback or crash resume.
