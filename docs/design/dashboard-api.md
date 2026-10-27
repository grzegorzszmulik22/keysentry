# Dashboard API routes

The contract between the dashboard screens (`src/dashboard/client/screens/*`, phase 3 Tasks 6a and 6b) and the
handlers the CLI provides (`DashboardApi`, phase 3 Task 7). Routes are served under `/api/<name>`. GET handlers
receive no input; reads that need parameters are POST routes with `mutating: false`. Every response is
secret-free except `reveal`. Shapes are TypeScript-like; `Cluster`, `PlanStep`, `RotationReport`, `TimelineEvent`,
`KeyHygiene`, `FirstRunResult`, `NotifyChannelKind` come from `src/types.ts`.

`mutating: true` routes need the CSRF header and a fresh passkey assertion for that exact route and body, and are
refused in read-only mode. `disarm` is deliberately `mutating: false` so that it never needs a passkey and works in
read-only mode.

## Reads (GET)

| Route | Response |
|---|---|
| `overview` | `{ firstRun: FirstRunResult \| null; connectedPlatforms: HostId[]; keys: number; inGitHistory: number; needsRotation: number; autopilot: 'off' \| 'armed' \| 'alert-only' \| 'disarmed'; nextSteps: string[] }` |
| `keys` | `{ keys: KeyView[] }` with `KeyView = { id; provider: ProviderId; tier: RiskTier; hint: string \| null; method: RotationMethod; places: { label: string; host: HostId; variable: string; writeOnly: boolean }[]; inGitHistory: boolean; ageDays?: number; rotateBy?: string; armed: boolean; state: 'ok' \| 'attention' \| 'stop'; stateText: string }` |
| `platforms` | `{ platforms: { host: HostId; name: string; connected: boolean; source?: 'vault' \| 'env'; roles: ('read' \| 'write')[]; tokens: { name: string; canReadValues: boolean; canWrite: boolean; scope: string; recommended: boolean; howToCreate: string; source: string }[]; keysentryUses: { scan: string; rotate: string } }[] }` |
| `access` | `{ items: { area: string; status: 'ok' \| 'warn' \| 'fail' \| 'info'; title: string; detail: string; fix?: string }[] }` (doctor items) |
| `network` | `{ allowed: { host: string; purpose: string; source: 'built in' \| 'added by you in keysentry.yaml' \| 'added by an environment variable' }[]; receipt: { host: string; purpose: string; count: number; blocked: number; lastAt: string }[] }` |
| `rotations` | `{ active: { planId: string; status: RotationReport['status']; startedAt: string; deadline?: string; steps: { clusterId: string; hint: string \| null; status: string; warnings: string[] }[] }[] }` |
| `autopilot` | `{ state: 'off' \| 'armed' \| 'alert-only' \| 'disarmed'; reasons: string[]; plan?: { id: string; keys: number; hosts: HostId[]; expiresAt: string; graceMinutes: number }; waves: { id: string; incident: string; status: string; deadline?: string }[]; lastNotificationAt: string \| null; needsRefresh: boolean }` |
| `autopilot/eligibility` | `{ eligible: { id: string; hint: string \| null; provider: ProviderId; needsAdoption: boolean }[]; ineligible: { id: string; hint: string \| null; reason: string }[]; lastDrillAt: string \| null }` |
| `activity` | `{ verify: { ok: boolean; problem?: string }; entries: { at: string; kind: string; summary: string }[] }` (newest first, at most 200) |
| `notifications` | `{ channels: { id: string; kind: NotifyChannelKind; label: string; lastSuccessAt: string \| null }[]; deviceKeyId: string }` |
| `approvals` | `{ pending: { id: string; kind: string; summary: string; createdAt: string; expiresAt?: string; source: 'monitor' \| 'autopilot' }[] }` |
| `settings` | `{ graceMinutes: number; rotateEveryDays: number; spendCapsUsd: Record<string, number>; digestDay: 'mon' \| 'tue' \| 'wed' \| 'thu' \| 'fri' \| 'sat' \| 'sun' \| 'off'; showHints: boolean }` |
| `hygiene` | `{ keys: KeyHygiene[] }` |

## Reads with input (POST, `mutating: false`)

| Route | Body | Response |
|---|---|---|
| `rotate/preview` | `{ clusterIds: string[] }` | `{ planId: string; planHash: string; changes: string[]; steps: { clusterId: string; hint: string \| null; method: RotationMethod; services: string[] }[]; warnings: string[] }` (`changes` are the plain sentences the confirm dialog repeats) |
| `drill` | `{}` | `{ score: number; reasons: string[]; elapsedMs: number }` |
| `timeline` | `{ id: string }` (plan or wave id) | `{ events: TimelineEvent[]; markdown: string }` |
| `card` | `{ platform: boolean; counts: boolean }` | `{ svg: string; score: number }` |
| `notifications/verify` | `{ code: string }` | `{ valid: boolean; message: string }` |
| `autopilot/disarm` | `{}` | `{ state: 'disarmed' }` (no passkey, works read-only) |

## Changes (POST, `mutating: true`, passkey)

| Route | Body | Response |
|---|---|---|
| `vault/store` | `{ name: string; role: 'read' \| 'write'; value: string }` | `{ stored: true }` |
| `vault/remove` | `{ name: string; role: 'read' \| 'write' }` | `{ removed: boolean }` |
| `rotate/execute` | `{ planId: string; planHash: string }` | `{ report: RotationReport }` (grace defers; the screen then offers finish/undo) |
| `rotation/finish` | `{ planId: string; early: boolean }` | `{ report: RotationReport }` |
| `rotation/undo` | `{ planId: string; clusterIds?: string[] }` | `{ restored: string[]; unavailable: { clusterId: string; reason: string }[] }` |
| `autopilot/arm` | `{ clusterIds: string[]; adopt: string[]; graceMinutes: number; maxServices: number; validDays: number }` | `{ planId: string; expiresAt: string; refused: { id: string; reason: string }[] }` |
| `notifications/add` | `{ kind: NotifyChannelKind; label: string; settings: Record<string, string> }` | `{ id: string }` |
| `notifications/remove` | `{ id: string }` | `{ removed: boolean }` |
| `notifications/test` | `{}` | `{ delivered: string[]; failed: { id: string; reason: string }[] }` |
| `approvals/approve` | `{ id: string }` | `{ result: string }` |
| `approvals/dismiss` | `{ id: string }` | `{ dismissed: true }` |
| `settings/update` | `Partial<settings>` | the new settings |
| `spend-limits/apply` | `{ clusterIds: string[] }` | `{ applied: { clusterId: string; limitUsd: number }[]; skipped: { clusterId: string; reason: string }[] }` |
| `reveal` | `{ clusterId: string }` | `{ value: string }` (only for readable values; the screen masks it and offers copy with 30 s clipboard clear) |

## Notification channel settings (`notifications/add`)

Field names follow `src/notify/channels`: Telegram `botToken`, `chatId`; Discord and Slack `webhookUrl`; ntfy
`server`, `topic`, optional `token`; generic webhook `url`; Resend `apiKey`, `from`, `to`; SMTP `host`, `port`
(`"465"` or `"587"`, converted to a number by the handler), `username`, `password`, `from`, `to`; console: none.
Secret fields (`botToken`, `webhookUrl`, `token`, `url`, `apiKey`, `password`) go to the vault, never to config. The
handler validates every field again (the screen's checks are a convenience) and so do `autopilot/arm` (positive
`maxServices`, `validDays` 1–365, `graceMinutes` ≥ 0, a drill in the last 24 hours) and `settings/update`.
`autopilot/disarm` must also cancel any arming that is still in progress, so a disarm always wins.
