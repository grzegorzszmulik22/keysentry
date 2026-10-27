# What keysentry can access

You can start with local files and add platforms when you need them. You do not need a keysentry account. A scan reads; an approved rotation can create a replacement key, update the consumers you selected, redeploy them and revoke the old key when the checks permit it.

There are two different permission questions: **what your token allows**, and **what keysentry does with it**. Railway, Vercel and Render do not document a read-only token that can read all the variable values needed for a scan. Their tokens can allow writes even while keysentry is only scanning. Use the narrowest token below, and review `keysentry doctor` before rotating.

This page describes phase 1 and vendor documentation checked on 27 October 2026. The [research notes](../notes/phase1-facts.md) record the evidence and its limits. Adapters have been tested against fakes, **not live accounts**. There has been **no external audit yet**. An item marked unverified is not a promise that the platform will accept that operation with that token.

## Local files and saved data

The dotenv adapter reads configured project roots for `.env` and `.env.*` files, excluding common build, dependency, state and template paths. It writes only the variable names selected for an approved rotation, preserves other content and does not create plaintext backup copies. This adapter makes no network requests.

Tokens and keysentry's encryption and signing keys belong in the OS vault: macOS Keychain, Windows DPAPI for the current user, or Linux Secret Service. An encrypted-file fallback needs your consent and a passphrase. Environment credentials remain available for CI; `doctor` explains that they give less separation from other processes. A separate read-role token may be stored where the provider supports one; a token stored for the read role is never used as the write token. Without a separate read token, scanning may use the base token or an environment credential.

Saved inventory, plans and rotation state are encrypted. During a rotation, new values and readable old values are encrypted under a per-rotation key until the rotation, including its grace period, is settled. The per-rotation key is then removed and the encrypted copies are deleted. A partial or deferred rotation keeps the copies needed to resume. The audit log and network receipt hold metadata, never full secret values. Names, times and short hints can still reveal information about your project; keep these files private.

## Hosting platforms

### Railway

**Choose:** a project token for one environment of one project, for scanning and approved writes. Use a workspace token only when you need several projects in that workspace. A project token uses the `Project-Access-Token` header; account and workspace tokens use a Bearer header. Railway CLI names distinguish `RAILWAY_TOKEN` (project) from `RAILWAY_API_TOKEN` (account/workspace). See [API authentication](https://docs.railway.com/integrations/api) and [CLI authentication](https://docs.railway.com/cli).

| Token type | What it can read | What it can change | Scope and creation |
|---|---|---|---|
| Account | Readable variable values | Variables and deployments | Personal resources and workspaces you belong to; create at [account tokens](https://railway.com/account/tokens), choosing No workspace |
| Workspace | Readable variable values | Variables and deployments | One workspace; choose that workspace on the same token page |
| Project | Readable values in its environment | Variables and deployments in that scope | One environment of one project; Project Settings → Tokens |
| OAuth | According to the approved scopes | According to the approved scopes | Login with Railway; keysentry does not implement an OAuth sign-in flow |

The project-token scope and header are documented. That every needed variable and discovery call is permitted with this token is **unverified against a live account**; the Railway CLI uses the same variable operations with project tokens. No read-only token type is documented. Sealed values cannot be retrieved; keysentry records their names as sealed. See [variables](https://docs.railway.com/variables) and [variable API operations](https://docs.railway.com/integrations/api/manage-variables).

keysentry sends GraphQL requests to `https://backboard.railway.com/graphql/v2`:

- Scan: project/project-token discovery, projects, environments, services and `variables(..., unrendered: true)`, including shared environment variables.
- Approved write: `variableCollectionUpsert` with `replace: false`, changing only the requested variables. `skipDeploys: true` stages writes during a rotation; Railway otherwise deploys by default.
- Activation: reads the latest deployment, calls `deploymentRedeploy` or `environmentTriggersDeploy`, then reads `deployment` status. A schema-compatibility path uses `serviceInstanceDeployV2`. Shared variables have no deployment of their own; referencing services need activation.

### Vercel

**Choose:** a project token with an expiry. There is no documented read-only option on the token page. A project token cannot mint another token. See [access tokens](https://vercel.com/docs/accounts/access-tokens) and [create a token](https://vercel.com/account/tokens).

| Token scope | What it can read | What it can change | Boundary |
|---|---|---|---|
| Full Account | Config values; Secret values remain opaque | Variables and deployments | Personal account and teams; a team selector is needed for team resources |
| Team | Config values; Secret values remain opaque | Variables and deployments | All projects in one team |
| Project | Config values; Secret values remain opaque | Resources in one project | One project; choose a team and project when creating it |

The environment model uses **Config** for values readable after save and **Secret** for values that cannot be read back. Legacy Sensitive variables are Secret. This is separate from the token scope. Enterprise Project Viewer can inspect environment variables without making changes, but whether tokens inherit that role restriction is **undocumented and unverified**. Permission for project tokens to call every environment/deployment endpoint below is inferred from the documented project scope and has not been live-tested. See [environment variable visibility](https://vercel.com/docs/environment-variables/sensitive-environment-variables) and [roles](https://vercel.com/docs/rbac/access-roles).

keysentry uses `https://api.vercel.com` with a Bearer token and an optional `teamId`:

- Scan: `GET /v10/projects`, `GET /v10/projects/{project}/env` and `GET /v1/projects/{project}/env/{id}` for readable values. Secret/Sensitive and ambiguous branch overrides are treated as sealed.
- Approved write: `PATCH /v9/projects/{project}/env/{id}` for an existing entry, or `POST /v10/projects/{project}/env?upsert=true` for a missing one. An entry shared by several targets updates that same value across those targets. Environment writes do not deploy.
- Activation: production uses `GET /v9/projects/{project}`, `GET /v6/deployments`, `POST /v13/deployments` and `GET /v13/deployments/{id}`. Rollback-pinned production can remain unconfirmed. Preview/development changes apply on a later deployment; the adapter does not start one.

See the [Vercel REST API](https://vercel.com/docs/rest-api). The API also offers environment-variable deletion, but the adapter does not use it.

### Render

**Choose:** a Render API key. There is no documented read-only, per-workspace or per-service key. The key can reach every workspace its user can access. A dedicated user limited to the target workspace may reduce access, but that setup has **not been verified**. Create a key in [account settings](https://dashboard.render.com/u/settings?add-api-key); see [API authentication](https://render.com/docs/api).

| Token | What it can read | What it can change | Boundary |
|---|---|---|---|
| User API key | Variable values, secret-file contents and environment-group values | Variables, secret files, groups and deployments | All workspaces accessible to the user |

keysentry uses a Bearer token at `https://api.render.com/v1`:

- Scan: `GET /services` and `GET /services/{service}/env-vars`.
- Approved write: `PUT /services/{service}/env-vars/{name}` for each selected variable. It does not use the full-set replacement endpoint.
- Activation: `GET /services/{service}/deploys` to find the live commit, `POST /services/{service}/deploys`, then `GET /services/{service}/deploys/{deployment}`. When a live Git commit is available, the deploy uses that commit rather than a newer branch commit.

The token is broader than this adapter: it currently does not scan secret files or environment groups. See the [Render endpoint reference](https://api-docs.render.com/llms.txt).

### Fly.io

**Choose:** an app deploy token for the selected app. For discovery, configure the app names where possible. An organization is needed to list apps. A read-only org token exists, but whether it can list secret names is **unverified**. Do not use an account auth token as the default integration token. See [Fly tokens](https://docs.fly.io/security/tokens).

| Token type | Platform capability | Boundary and creation |
|---|---|---|
| Auth | Full user access | All the user's organizations/apps; `fly auth login`, then `fly auth token` |
| Org deploy | Manage apps | One org; `fly tokens create org --name N --expiry D` |
| App deploy | Manage the app and its resources | One app; `fly tokens create deploy -a app --expiry D` |
| Read-only | Read org resources | One org; `fly tokens create readonly` |
| SSH | SSH to an app and org WireGuard access | `fly tokens create ssh -a app`; not needed by keysentry |
| Machine-exec | Run specified commands, or all commands if unrestricted | `fly tokens create machine-exec --command ...`; not needed by keysentry |
| WireGuard | Manage WireGuard peers | `fly tokens create wireguard`; not needed by keysentry |

Choose an explicit short expiry: the recorded default is 20 years. Tokens can be narrowed with caveats using `fly tokens attenuate`. Creation and attenuation are implemented in [flyctl token commands](https://github.com/superfly/flyctl/tree/master/internal/command/tokens).

keysentry reads app names through `GET https://api.machines.dev/v1/apps?org_slug=...` unless names are configured. It reads secret names, digests and creation times with GraphQL at `https://api.fly.io/graphql`, and treats every value as sealed. Approved changes use `setSecrets` with `replaceAll: false` and `stage: true`. Support for that staging field has not been checked against a live account; a rejected request is not retried without staging. Activation is manual: `fly secrets deploy -a <app>`; keysentry does not confirm the deployment itself.

Fly's [secret documentation](https://docs.fly.io/apps/secrets) says plaintext cannot be read back. The [Machines API specification](https://docs.fly.io/api/machines/openapi.json) nevertheless describes `show_secrets=true` and a secret `value` field. Whether this returns values, and with which token, is **unverified**; this adapter does not use it. The [Machines API reference](https://docs.fly.io/llms.txt) also describes secret-write endpoints and secret versions for machine updates. Deploy access can run application code that reads secrets, even when the secret-listing API does not reveal them.

### GitHub Actions

**Choose:** a fine-grained PAT limited to selected repositories, with **Secrets: read** to list names and **Secrets: write** when writing replacements. No token can read repository Actions secret values. Create one at [fine-grained token settings](https://github.com/settings/personal-access-tokens/new). See [fine-grained permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens).

| Token | What it can read | What it can change | Boundary |
|---|---|---|---|
| Fine-grained PAT | Secret names/metadata and encryption public key with Secrets: read | Repository secrets with Secrets: write | Selected repositories of one owner |
| Classic PAT / OAuth | Secret names/metadata; never values | Repository secrets with `repo` scope | Repositories the user can access, broader than a selected-repo PAT |

keysentry uses a Bearer token at `https://api.github.com`. It lists `GET /repos/{owner}/{repo}/actions/secrets`, reads `GET .../actions/secrets/public-key`, encrypts the replacement locally with GitHub's public key, and writes `PUT .../actions/secrets/{name}`. It does not dispatch or rerun workflows: new secrets apply on the next run. See [Actions secrets endpoints](https://docs.github.com/en/rest/actions/secrets).

Actions **variables** are different: their values are readable with Variables: read, and writes need Variables: write. The current adapter scans repository secrets only; readable variables are not yet included. Dispatching or rerunning a workflow would require Actions: write, which this adapter does not need. `doctor --probe` can call `GET /user`. OAuth scope response headers describe classic/OAuth tokens; an endpoint's accepted-permissions header describes what the endpoint needs, not a complete inventory of a fine-grained token's grants. See [OAuth scopes](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps).

## Providers that issue your application keys

Host access reads or replaces a copy of a key. Provider access creates or retires the key at its issuer. Keep the two separate. A scan does not need an organization admin key merely to identify a local value. Verification can send the value to the issuer's read/authentication endpoint. These calls do not invoke an AI model or send prompts.

| Provider | Credential and narrowest available choice | Reads and verification used by keysentry | Approved writes used by keysentry |
|---|---|---|---|
| OpenAI | `OPENAI_ADMIN_KEY`, an organization Admin API key; application keys alone do not grant management access | At `api.openai.com`: `GET /v1/models` with the application key; `GET /v1/organization/projects`, project `api_keys`, and `/v1/organization/usage/completions` with the admin key | For an existing service account with explicit copyable scopes, `POST /v1/organization/projects/{project}/service_accounts/{account}/api_keys`; revoke only the old key with `DELETE /v1/organization/projects/{project}/api_keys/{id}`. Otherwise guided |
| Anthropic | `ANTHROPIC_ADMIN_KEY`, an Admin API key; admin role required to create it; no selectable scopes are documented | At `api.anthropic.com`: `GET /v1/models` with the application key; `GET /v1/organizations/api_keys` and `/v1/organizations/usage_report/messages` with the admin key | Replacement creation is guided in the Console. Revocation/containment uses `POST /v1/organizations/api_keys/{id}` with `status: inactive`, immediately stopping consumers of that key |
| OpenRouter | `OPENROUTER_PROVISIONING_KEY`; the vendor now calls it a **Management API key**. Account-level management access, not workspace-scoped | At `openrouter.ai`: `GET /api/v1/key` with the application key; `GET /api/v1/keys` with the management key, including limits and cumulative usage | `POST /api/v1/keys` to create a replacement, `DELETE /api/v1/keys/{hash}` to revoke, or `PATCH .../{hash}` with `disabled: true` for approved containment |
| Resend | `RESEND_ADMIN_KEY` with `full_access`; a domain-limited `sending_access` key cannot manage keys | At `api.resend.com`: `GET /domains` for verification and `GET /api-keys` with the management credential | `POST /api-keys` creates the replacement; `DELETE /api-keys/{id}` can revoke a known key. The adapter cannot reliably identify the previous key from its value; it leaves deletion of that old key to you |
| Cloudflare | `CLOUDFLARE_ADMIN_TOKEN` with **API Tokens Write** for user tokens; do not substitute a global API key | At `api.cloudflare.com`: `GET /client/v4/user/tokens/verify` with the token being rotated | `PUT /client/v4/user/tokens/{id}/value` rolls the value. This is atomic: the old value stops working immediately, before consumer updates; no overlap or undo of that value |
| AWS | The existing IAM user's access-key pair, from sibling `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` variables (or matching prefixed names); self-management permissions on that user | SigV4-signed `POST https://sts.amazonaws.com/` with `GetCallerIdentity` | SigV4-signed `POST https://iam.amazonaws.com/` with `CreateAccessKey` and `DeleteAccessKey`. The access key ID and secret are updated together. Temporary session credentials are not automatically rotated |

OpenAI Admin API keys cannot call normal model endpoints. Their authority is broader than this adapter: the API can list/create/delete organization admin keys at `/v1/organization/admin_api_keys`, and update project-key scopes/expiry with `POST /v1/organization/projects/{project}/api_keys/{id}`. It can create a service account and its first key, or another key on an existing service account; it does **not** create user-owned project keys. The adapter deliberately uses the existing service account and explicit scopes, rather than creating a broader replacement. Project-key listings return redacted values. The statement that only organization Owners can create admin keys was not fully verified in the recorded research. See [OpenAI administration](https://developers.openai.com/api/reference/administration/overview) and the [OpenAPI definition](https://github.com/openai/openai-openapi/blob/main/openapi.json).

Anthropic offers key listing and status changes, **no create or delete endpoint**. New keys must be created in [Console key settings](https://platform.claude.com/settings/keys). Its API also accepts certain organization admin OAuth/non-workspace credentials; keysentry currently supplies the configured admin key with `x-api-key`. Service-account creation is a workload-identity flow and does not return a replacement API key. See [API key management](https://platform.claude.com/docs/en/api/organization/api_keys), [Admin API](https://platform.claude.com/docs/en/manage-claude/admin-api), [admin keys](https://platform.claude.com/docs/en/manage-claude/admin-api-keys) and [service-account creation](https://platform.claude.com/docs/en/api/organization/service_accounts/create).

OpenRouter Management API keys cannot call completion endpoints. For organizations, an org admin creates them at [management-key settings](https://openrouter.ai/settings/management-keys); expiration is fixed at creation. The API can edit per-key limits and disable keys. See [management keys](https://openrouter.ai/docs/guides/overview/auth/management-api-keys) and the [API reference index](https://openrouter.ai/docs/llms.txt).

Resend's `full_access` credential can manage more than keys, including email resources; its authority is broader than the operations above. Key values are shown once. The API's key update endpoint edits the name; permission/domain changes belong in the dashboard. See [key permissions](https://resend.com/docs/dashboard/api-keys/introduction) and [create an API key](https://resend.com/docs/api-reference/api-keys/create-api-key).

Cloudflare also documents account-owned token rolls with **Account API Tokens Write** at `/client/v4/accounts/{account}/tokens/{id}/value`; the current adapter implements the user-token path only. A roll preserves permissions but replaces the value immediately. The API Tokens Edit label in the additional-token creation template should not be confused with the roll permission. See [user-token roll](https://developers.cloudflare.com/api/resources/user/subresources/tokens/subresources/value/methods/update/), [roll behavior](https://developers.cloudflare.com/fundamentals/api/how-to/roll-token/) and [token creation permissions](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/).

AWS allows at most **two access keys per IAM user, including inactive keys**. Automatic rotation needs `iam:CreateAccessKey` and `iam:DeleteAccessKey` on the calling user. The documented self-management policy also includes `iam:ListAccessKeys`, `iam:UpdateAccessKey`, `iam:GetAccessKeyLastUsed` and `iam:GetUser`, with optional `iam:TagUser`; keysentry does not currently call all of these. Limit the resource to the intended user, not every user. See [required permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys_required-permissions.html) and [self-managed access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-key-self-managed.html).

Usage costs calculated from OpenAI or Anthropic token counts are estimates from editable price tables, not billing statements.

### Guided and local providers

These adapters do not receive a separate organization management token. Give the replacement the same required application access, using the issuer's own settings. A result labelled `unverified` means keysentry did not test application access; it does not prove the replacement works.

| Provider | Read or verification call | How rotation happens |
|---|---|---|
| Stripe | `GET https://api.stripe.com/v1/balance` with the application key; restricted-key 403 can mean valid but limited. Webhook signing secrets are unverified | You create/roll a key in [Stripe API keys](https://dashboard.stripe.com/apikeys), or roll the webhook secret in its endpoint settings |
| GitHub application token | `GET https://api.github.com/user` | You create the replacement with the needed repository/organization permissions in [token settings](https://github.com/settings/tokens) |
| Supabase | If `SUPABASE_URL` is configured, `GET <project-origin>/rest/v1/` with `apikey` and Bearer headers; otherwise unverified. The egress guard must permit the project host | You replace the key in the [project dashboard](https://supabase.com/dashboard); rotating a legacy JWT signing secret can affect other keys and sessions |
| Slack | For `xox...` tokens, `POST https://slack.com/api/auth.test` with an empty body; webhook URLs are unverified and are not called | You replace the token or webhook in the [issuing Slack app](https://api.slack.com/apps) |
| SendGrid | `GET https://api.sendgrid.com/v3/scopes` with the application key | You create a suitably scoped replacement in [API key settings](https://app.sendgrid.com/settings/api_keys) |
| Twilio | No verification request; unverified | You use the [Twilio Console](https://console.twilio.com/) secondary-token or API-key flow and update the matching identifier too |
| Google API/service-account keys | No verification request; unverified | You create a restricted replacement in [Cloud credentials](https://console.cloud.google.com/apis/credentials) or IAM and test the application's actual API calls |
| Database credentials | No database connection or verification request; unverified | You change the credential at the database first, using your provider or database administrator; changing only the connection URL is insufficient |
| Private keys | No verification request; unverified | You generate the replacement with the appropriate trusted tool, update verifier trust, and test before removing the old public key/certificate |
| Wallet keys or seeds | No verification request; unverified | You create a new wallet and move funds/permissions with a trusted wallet tool. Replacing a variable does not protect the old wallet |
| Application/session secrets | Generated locally with Node cryptography; no issuer request | Approved rotation writes a new random value to selected consumers; existing sessions may be affected |
| Data-encryption keys | No verification request; unverified | You use the application's data migration procedure. Existing data must be re-encrypted and checked before retiring an old key |
| Unknown credentials | No verification request; unverified | Identify the issuer and use its documented replacement flow before updating consumers |

## Other network access

When monitoring is configured, keysentry can read provider usage/key metadata, GitHub secret-scanning alerts and configured advisory/status feeds, and can send configured notifications. Approval is required for provider or host mutations unless you explicitly enabled the relevant automatic policy. Notifications must not carry secret values; a channel can still see whatever project metadata you choose to send. Signed notifications, passkey approvals and the new armed autopilot workflow are later phases, not phase 1 guarantees.

An explicit `keysentry verify` can fetch `SHA256SUMS` and `SHA256SUMS.sig` from `https://github.com/grzenio22/keysentry/releases/download/v<version>/` through the same guarded client. The release key list is empty in this phase, so online signature verification reports **unconfigured** until a trusted public key is embedded. Offline integrity compares the bundle with the adjacent manifest; it is not independent evidence of who published both files.

All application requests use the injected `HttpClient`; the CLI uses an HTTPS egress allow-list and records each attempt's host, method, purpose, time, allowed/blocked outcome and available HTTP status. It records no headers, request/response bodies or secret-bearing URLs. `keysentry network` shows that receipt. A host on the allow-list can still be compromised; the receipt is a record, not proof that a response was truthful.

The Node permission sandbox is an additional file/process limit. On Node 22 it is enabled only from **22.23.4** onward; Node 22 has no `--allow-net` control. The in-client egress guard is the network control. See [recorded Node versions and advisories](../notes/phase1-facts.md#4-nodejs-permission-model-versions). Agent-environment checks also have limits: `CLAUDECODE=1` alone occurs in human IDE terminals, while dedicated child-session and other documented agent markers are used to refuse mutations. They do not isolate keys from other software running as your user.

## Things keysentry never does

- Send your keys to keysentry's company, a model, analytics service or an unconfigured collection endpoint.
- Ask for a keysentry account, run telemetry, self-update or check for updates silently.
- Turn a scan into a variable update, deployment or provider-key revocation.
- Retrieve plaintext GitHub Actions secrets, or claim that an opaque host value has been read.
- Delete unrelated variables or replace a platform's whole variable set as part of an update.
- Put secret values in command arguments, helper-process environments, logs, audit records or the network receipt.
- Treat an unverified result, a successful variable write, or a queued deployment as proof that every application is using the replacement.
- Expose an MCP server or agent skill for acting on keys. Known AI coding-agent environments are refused for mutations; agents may suggest commands for you to run in your normal terminal.

Read the [threat model](THREAT-MODEL.md) for the limits around same-user software, the operating system and compromised providers. Team roles, shared approval rules, cloud boxes and confidential-computing claims are outside this phase.
