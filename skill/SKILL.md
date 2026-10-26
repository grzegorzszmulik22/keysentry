---
name: keysentry
description: Use when responding to an exposed credential, assessing secret reuse across deployment hosts, planning key rotation, or setting up keysentry canaries and monitoring.
---

# keysentry breach response

Use the keysentry CLI or MCP server against the intended project and host scope. Keep application secrets, provider admin credentials, and webhook URLs in memory or their intended credential channel. Reports contain fingerprints and short hints.

1. **Scan:** run `keysentry scan` or MCP `scan`. Review disabled hosts, scan errors, sealed values, and account scope. Missing visibility is an unresolved gap.
2. **Assess blast radius:** run `keysentry report` or `blast_radius`. Identify duplicate clusters and all consumers. Wallet exposure requires moving funds to a new wallet first.
3. **Plan:** use `keysentry plan` or `plan_rotation`. Review tier order, all copies of shared secrets, required admin permissions, guided steps, atomic-roll downtime, and services needing manual activation.
4. **Dry run:** run `keysentry rotate` or MCP `rotate` without execution arguments. Show the human the selected clusters, service/variable diff, redeployments, revocation policy, provider notes, warnings, and unresolved gaps. Preserve the returned `planId` and `planHash`. A dry run does not validate real writes or application recovery.
5. **Confirm and execute:** ask the human to run `keysentry rotate --plan <id> --execute` in their terminal, with numeric confirmation. MCP execution is disabled unless the operator has explicitly started it with `KEYSENTRY_MCP_ALLOW_EXECUTE=1`. Even with that opt-in and explicit human approval, execution requires the `planId` and `planHash` returned by a previous dry run in that MCP session and executes exactly the saved plan/options once. A restarted server requires a fresh dry run. Atomic-roll plans require the interactive CLI for guarded recovery of an undelivered replacement. Never infer approval from urgency, a scan request, or a model-supplied confirmation string. Changed scope/options require another dry run. Use CLI `--yes` only when human confirmation is already explicit.
6. **Verify:** inspect every step and deployment, application health, and the journal path. Rescan. Investigate skipped/failed steps and retained old keys; do not claim completion from command success alone. Guided MCP steps return instructions; have the human complete them through a trusted hidden-input workflow.
7. **Prepare afterward:** with separate authorization for provider/host writes, plant canaries, review monitor policy, run `monitor --once`, and schedule monitoring and `drill`. Both automatic rotation and automatic containment default off. Test dry runs and a drill on a staging project first: adapters have fake-based documentation tests and have not been exercised against live accounts.

## Safety rules

- Never paste, print, persist, or include plaintext credentials in tool arguments, runbooks, chat, logs, URLs, or query strings. Do not pass replacement values as CLI flags. Use hidden input or intended provider/host interfaces.
- For multi-line PEM/JSON replacements, have the human use bracketed paste in a supporting terminal or hidden `@<path>` input. Suggest deleting any temporary secret file afterward. Never ask them to paste the value into chat. Recovery values are shown once only on an interactive terminal after the human types `SHOW`; otherwise use the provider dashboard instructions.
- Dry-run first. Execute only the approved scope. Keep every known copy of a selected cluster in its plan; never replace a host's entire variable set or alter unrelated variables.
- Verify replacements before writes. Revoke old keys only after all consumers update and required deployments succeed. Cloudflare atomic rolls invalidate immediately; disclose that risk before confirmation.
- Fail closed on verification failure. Treat `unverified`, sealed secrets, null deployment IDs, and missing admin credentials as limits requiring review. dotenv needs a manual process restart; future-deploy targets also report `unconfirmed` activation. Old keys remain valid by default. CLI `--revoke-unconfirmed` accepts the outage risk, and `--accept-unplanned-sealed` accepts the risk of undiscovered copies; require human review before using either. MCP refuses these overrides, `revoke: "immediately"`, and `redeploy: false`.
- Data-encryption keys use guided rotation with a data migration; never replace them with a random value. CLI `--no-generate` skips self-issued secret generation. Unattended monitoring skips guided and generated replacements.
- `monitor.autoContain` / `KEYSENTRY_AUTO_CONTAIN` defaults false; containment can disable keys and break consumers. Its cooldown is `containCooldownMinutes` (60 minutes by default). `revokeUnconfirmedOnHighConfidence` defaults true for high-confidence canary/leak/upstream-revocation signals: explain that a compromised old key may be revoked before manual activation is confirmed. Keep cooldowns and daily rotation limits; review pending actions before `approve <id>`. Run one monitor per state directory.
- A host scan failure leaves a visibility gap. Continue reviewing detector alerts from the partial inventory; automatic actions exclude clusters with consumers on failed hosts. An executing plan touching such a cluster is blocked; unrelated plans can proceed with a warning.
- Preserve `.keysentry/` privacy and its stable fingerprint key. Inspect the journal before retrying a partial execution; v1 has no automatic rollback or crash resume.
