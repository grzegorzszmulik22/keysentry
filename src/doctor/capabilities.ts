/** Verified facts and caveats: notes/phase1-facts.md §1 (2026-10-27). These are token
 * types, not an assertion that a supplied opaque credential has a particular scope. */
export interface TokenCapability {
  name: string;
  canReadValues: boolean;
  canWrite: boolean;
  scope: string;
  recommended: boolean;
  howToCreate: string;
  source: string;
}

export interface PlatformCapabilities {
  platform: string;
  tokens: TokenCapability[];
  keysentryUses: { scan: string; rotate: string };
  source: string;
}

export const TOKEN_CAPABILITIES: Record<string, PlatformCapabilities> = {
  railway: {
    platform: 'Railway', source: 'https://docs.railway.com/integrations/api',
    tokens: [
      { name: 'Project token', canReadValues: true, canWrite: true, scope: 'One environment of one project; variable endpoint access is inferred from Railway CLI usage.', recommended: true,
        howToCreate: 'Open your project at https://railway.com/dashboard and create a token in Project Settings > Tokens.', source: 'https://docs.railway.com/integrations/api' },
      { name: 'Workspace token', canReadValues: true, canWrite: true, scope: 'One workspace; no personal resources or other workspaces.', recommended: false,
        howToCreate: 'Create a token at https://railway.com/account/tokens and select the workspace.', source: 'https://docs.railway.com/integrations/api' },
      { name: 'Account token', canReadValues: true, canWrite: true, scope: 'Personal resources and all workspaces you belong to.', recommended: false,
        howToCreate: 'Create a token at https://railway.com/account/tokens and select No workspace.', source: 'https://docs.railway.com/integrations/api' },
      { name: 'OAuth token', canReadValues: true, canWrite: true, scope: 'Read and write access depend on the approved OAuth scopes.', recommended: false,
        howToCreate: 'Approve the needed scopes in Login with Railway through https://railway.com/dashboard.', source: 'https://docs.railway.com/integrations/api' },
    ],
    keysentryUses: { scan: 'Read variable values and metadata, excluding sealed values; no read-only token type is documented.', rotate: 'Write selected variables and redeploy services after approval.' },
  },
  vercel: {
    platform: 'Vercel', source: 'https://vercel.com/docs/accounts/access-tokens',
    tokens: [
      { name: 'Project token', canReadValues: true, canWrite: true, scope: 'One project; Config values are readable, Secret values are not; endpoint access is inferred from project resource access.', recommended: true,
        howToCreate: 'Create a token at https://vercel.com/account/tokens and select the team and project.', source: 'https://vercel.com/docs/accounts/access-tokens' },
      { name: 'Team token', canReadValues: true, canWrite: true, scope: 'All projects in one team; Config values only.', recommended: false,
        howToCreate: 'Create a token at https://vercel.com/account/tokens and select the team and All Projects.', source: 'https://vercel.com/docs/accounts/access-tokens' },
      { name: 'Full Account token', canReadValues: true, canWrite: true, scope: 'Personal account and all teams; Config values only.', recommended: false,
        howToCreate: 'Create a Full Account token at https://vercel.com/account/tokens.', source: 'https://vercel.com/docs/accounts/access-tokens' },
    ],
    keysentryUses: { scan: 'Read Config variable values and Secret names; no read-only token option is documented.', rotate: 'Write selected variables and redeploy production after approval; other targets apply on their next deployment.' },
  },
  render: {
    platform: 'Render', source: 'https://render.com/docs/api',
    tokens: [
      { name: 'API key', canReadValues: true, canWrite: true, scope: 'Every workspace accessible to the user; no read-only or service-scoped key is documented.', recommended: true,
        howToCreate: 'Create an API key in Account Settings at https://dashboard.render.com/u/settings?add-api-key.', source: 'https://render.com/docs/api' },
    ],
    keysentryUses: { scan: 'Read service environment variable values.', rotate: 'Update selected variables and deploy services after approval.' },
  },
  fly: {
    platform: 'Fly.io', source: 'https://docs.fly.io/security/tokens',
    tokens: [
      { name: 'Read-only token', canReadValues: false, canWrite: false, scope: 'Read access to one organization; secret names/digests access with this token is unverified.', recommended: true,
        howToCreate: 'Run fly tokens create readonly after signing in at https://fly.io/dashboard.', source: 'https://docs.fly.io/security/tokens' },
      { name: 'App deploy token', canReadValues: false, canWrite: true, scope: 'One app and its resources; plaintext secret read-back is not documented as available.', recommended: true,
        howToCreate: 'Run fly tokens create deploy -a APP --expiry DURATION for an app listed at https://fly.io/dashboard.', source: 'https://docs.fly.io/security/tokens' },
      { name: 'Org deploy token', canReadValues: false, canWrite: true, scope: 'Manage every app in one organization.', recommended: false,
        howToCreate: 'Run fly tokens create org --name NAME --expiry DURATION for an organization at https://fly.io/dashboard.', source: 'https://docs.fly.io/security/tokens' },
      { name: 'Auth token', canReadValues: false, canWrite: true, scope: 'All organizations and apps of the user; not recommended as the default API token.', recommended: false,
        howToCreate: 'Run fly auth login and fly auth token for the account at https://fly.io/dashboard.', source: 'https://docs.fly.io/security/tokens' },
      { name: 'SSH token', canReadValues: false, canWrite: false, scope: 'SSH to one app and organization WireGuard access; not a variable-management token.', recommended: false,
        howToCreate: 'Run fly tokens create ssh -a APP for an app at https://fly.io/dashboard.', source: 'https://docs.fly.io/security/tokens' },
      { name: 'Machine-exec token', canReadValues: false, canWrite: false, scope: 'Execute allowed commands on machines in one app; commands can expose secrets.', recommended: false,
        howToCreate: 'Run fly tokens create machine-exec with explicit allowed commands for an app at https://fly.io/dashboard.', source: 'https://docs.fly.io/security/tokens' },
      { name: 'WireGuard token', canReadValues: false, canWrite: false, scope: 'WireGuard peer management; not a variable-management token.', recommended: false,
        howToCreate: 'Run fly tokens create wireguard for an organization at https://fly.io/dashboard.', source: 'https://github.com/superfly/flyctl/blob/master/internal/command/tokens/create.go' },
    ],
    keysentryUses: { scan: 'List secret names and digests; do not rely on plaintext read-back or unverified read-only token access.', rotate: 'Write selected secrets after approval; phase 1 asks you to deploy them with the Fly CLI.' },
  },
  'github-actions': {
    platform: 'GitHub Actions', source: 'https://docs.github.com/en/rest/actions/secrets',
    tokens: [
      { name: 'Fine-grained PAT with Secrets: read', canReadValues: false, canWrite: false, scope: 'Selected repositories of one owner; names and metadata only; Variables: read is needed for variable values.', recommended: true,
        howToCreate: 'Create a fine-grained token at https://github.com/settings/personal-access-tokens/new for selected repositories with Secrets: read.', source: 'https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens' },
      { name: 'Fine-grained PAT with Secrets: write', canReadValues: false, canWrite: true, scope: 'Selected repositories of one owner; Actions: write is needed only for dispatching workflows.', recommended: true,
        howToCreate: 'Create a fine-grained token at https://github.com/settings/personal-access-tokens/new for selected repositories with Secrets: write.', source: 'https://docs.github.com/en/rest/actions/secrets' },
      { name: 'Classic PAT or OAuth token', canReadValues: false, canWrite: true, scope: 'The repo scope covers all accessible repositories; secret values cannot be read.', recommended: false,
        howToCreate: 'Create a classic token at https://github.com/settings/tokens with the repo scope.', source: 'https://docs.github.com/en/rest/actions/secrets' },
    ],
    keysentryUses: { scan: 'List secret names and metadata; no token can read Actions secret values.', rotate: 'Encrypt and write selected repository secrets after approval; values apply to the next workflow run.' },
  },
  openai: {
    platform: 'OpenAI', source: 'https://developers.openai.com/api/reference/administration/overview',
    tokens: [
      { name: 'Admin API key', canReadValues: false, canWrite: true, scope: 'Organization administration; cannot call non-admin endpoints or recover existing key values.', recommended: true,
        howToCreate: 'Create an Admin API key at https://platform.openai.com/settings/organization/admin-keys.', source: 'https://developers.openai.com/api/reference/administration/overview' },
    ],
    keysentryUses: { scan: 'List project key metadata to identify keys; existing plaintext key values are unavailable.', rotate: 'Create a service-account key and revoke the selected old key after approval; user-owned project keys have no create endpoint.' },
  },
  anthropic: {
    platform: 'Anthropic', source: 'https://platform.claude.com/docs/en/api/organization/api_keys',
    tokens: [
      { name: 'Admin API key', canReadValues: false, canWrite: true, scope: 'Organization administration; admin role required and no selectable scopes.', recommended: true,
        howToCreate: 'An organization admin can create an Admin API key at https://platform.claude.com/settings/admin-keys.', source: 'https://platform.claude.com/docs/en/manage-claude/admin-api-keys' },
      { name: 'OAuth token with org:admin', canReadValues: false, canWrite: true, scope: 'Organization administration; service-account creation makes WIF identities, not API keys.', recommended: false,
        howToCreate: 'Approve org:admin through the organization OAuth flow at https://platform.claude.com/settings.', source: 'https://platform.claude.com/docs/en/manage-claude/admin-api' },
      { name: 'Non-workspace personal or service-account key', canReadValues: false, canWrite: true, scope: 'Accepted by the Admin API for organization key management; no existing secret read-back.', recommended: false,
        howToCreate: 'Create a non-workspace personal or service-account key at https://platform.claude.com/settings/keys.', source: 'https://platform.claude.com/docs/en/api/organization/api_keys' },
    ],
    keysentryUses: { scan: 'List key metadata and usage reports.', rotate: 'Guide you to create a replacement in the Console and mark the old key inactive after approval; no API create or delete endpoint exists.' },
  },
  openrouter: {
    platform: 'OpenRouter', source: 'https://openrouter.ai/docs/guides/overview/auth/management-api-keys',
    tokens: [
      { name: 'Management API key (formerly provisioning key)', canReadValues: false, canWrite: true, scope: 'Account-level management across workspaces; cannot call completion endpoints.', recommended: true,
        howToCreate: 'Create a Management API key at https://openrouter.ai/settings/management-keys.', source: 'https://openrouter.ai/docs/guides/overview/auth/management-api-keys' },
    ],
    keysentryUses: { scan: 'List key metadata, usage and limits.', rotate: 'Create a replacement key, preserve its limit, and delete the selected old key after approval.' },
  },
  resend: {
    platform: 'Resend', source: 'https://resend.com/docs/dashboard/api-keys/introduction',
    tokens: [
      { name: 'Full-access API key', canReadValues: false, canWrite: true, scope: 'Create, delete, get and update any resource; key values are shown only at creation.', recommended: true,
        howToCreate: 'Create an API key with Full access at https://resend.com/api-keys.', source: 'https://resend.com/docs/api-reference/api-keys/create-api-key' },
      { name: 'Sending-access API key', canReadValues: false, canWrite: false, scope: 'Send email, optionally for one domain; cannot manage keys.', recommended: false,
        howToCreate: 'Create a Sending access API key and select a domain at https://resend.com/api-keys.', source: 'https://resend.com/docs/dashboard/api-keys/introduction' },
    ],
    keysentryUses: { scan: 'List key metadata using Full access; existing key values cannot be recovered.', rotate: 'Create a replacement and delete an identified old key after approval; sending-only access is insufficient.' },
  },
  cloudflare: {
    platform: 'Cloudflare', source: 'https://developers.cloudflare.com/fundamentals/api/how-to/roll-token/',
    tokens: [
      { name: 'User token with API Tokens Write', canReadValues: false, canWrite: true, scope: 'Manage user API tokens; rolling immediately invalidates the old value and preserves permissions.', recommended: true,
        howToCreate: 'Create a token with API Tokens Write at https://dash.cloudflare.com/profile/api-tokens.', source: 'https://developers.cloudflare.com/api/resources/user/subresources/tokens/subresources/value/methods/update/' },
      { name: 'Account token with Account API Tokens Write', canReadValues: false, canWrite: true, scope: 'Manage account-owned tokens; the phase 1 adapter only implements user-token rolling.', recommended: false,
        howToCreate: 'Create an account-owned token with Account API Tokens Write at https://dash.cloudflare.com.', source: 'https://developers.cloudflare.com/fundamentals/api/how-to/roll-token/' },
    ],
    keysentryUses: { scan: 'Verify token identity and status without recovering its value.', rotate: 'Roll a user token after approval; this atomic operation invalidates its previous value immediately.' },
  },
  aws: {
    platform: 'AWS', source: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys_required-permissions.html',
    tokens: [
      { name: 'IAM user access-key pair with self-management policy', canReadValues: false, canWrite: true, scope: 'Only the calling IAM user: CreateAccessKey, DeleteAccessKey, ListAccessKeys, UpdateAccessKey, GetAccessKeyLastUsed and GetUser; maximum two keys including inactive keys.', recommended: true,
        howToCreate: 'Create an access-key pair and attach the self-management policy for your IAM user at https://console.aws.amazon.com/iam/home#/security_credentials.', source: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-keys_required-permissions.html' },
    ],
    keysentryUses: { scan: 'Identify the caller and list access-key metadata; existing secret access keys cannot be read back.', rotate: 'Create a replacement IAM user key pair and delete the selected old key after approval; temporary role credentials are not rotated this way.' },
  },
  // Phase 6 deploy platforms (notes/hosts-a.md, notes/hosts-b.md; docs read 2026-10-28).
  netlify: {
    platform: 'Netlify', source: 'https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api/',
    tokens: [
      { name: 'Personal access token', canReadValues: true, canWrite: true, scope: 'Acts as your user on every team you belong to; secret values are write-only except their dev value, and shared team variables need a Team Owner. No read-only or site-scoped token is documented.', recommended: true,
        howToCreate: 'Create a token with an expiration date under Applications > Personal access tokens at https://app.netlify.com/user/applications#personal-access-tokens.', source: 'https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api/' },
      { name: 'OAuth2 access token', canReadValues: true, canWrite: true, scope: 'Issued to a registered OAuth application by the approving user; no narrower scopes are documented.', recommended: false,
        howToCreate: 'Register an OAuth application at https://app.netlify.com/user/applications and complete the authorization flow.', source: 'https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api/' },
    ],
    keysentryUses: { scan: 'Read site and shared team variable values per deploy context; secret values stay sealed.', rotate: 'Update selected context values and rebuild the published production commit after approval; previews, branch deploys and shared variables apply on their next deploy.' },
  },
  heroku: {
    platform: 'Heroku', source: 'https://devcenter.heroku.com/articles/oauth',
    tokens: [
      { name: 'OAuth authorization with read-protected and write-protected', canReadValues: true, canWrite: true, scope: 'Every app and resource of the account including config vars; excludes account information.', recommended: true,
        howToCreate: 'Run heroku authorizations:create --scope read-protected,write-protected --expires-in SECONDS after signing in at https://dashboard.heroku.com.', source: 'https://devcenter.heroku.com/articles/oauth' },
      { name: 'OAuth authorization with read-protected', canReadValues: true, canWrite: false, scope: 'Read every app and resource including config vars; cannot change them.', recommended: true,
        howToCreate: 'Run heroku authorizations:create --scope read-protected --expires-in SECONDS after signing in at https://dashboard.heroku.com.', source: 'https://devcenter.heroku.com/articles/oauth' },
      { name: 'OAuth authorization with read and write', canReadValues: false, canWrite: false, scope: 'Apps and resources excluding config vars; not enough for keysentry.', recommended: false,
        howToCreate: 'Run heroku authorizations:create --scope read,write after signing in at https://dashboard.heroku.com.', source: 'https://devcenter.heroku.com/articles/oauth' },
      { name: 'API key or global authorization', canReadValues: true, canWrite: true, scope: 'Read and write access to the whole account, like a CLI login; personal direct authorizations do not expire.', recommended: false,
        howToCreate: 'Run heroku auth:token, or reveal the API key in Account settings at https://dashboard.heroku.com/account.', source: 'https://devcenter.heroku.com/articles/oauth' },
    ],
    keysentryUses: { scan: 'Read app config var values.', rotate: 'Update selected config vars after approval; Heroku creates a release and restarts the app for every update.' },
  },
  digitalocean: {
    platform: 'DigitalOcean App Platform', source: 'https://docs.digitalocean.com/reference/api/scopes/',
    tokens: [
      { name: 'Custom-scope token with app:read and app:update', canReadValues: true, canWrite: true, scope: 'View and modify App Platform apps of one team within your team role; SECRET values are returned encrypted.', recommended: true,
        howToCreate: 'Generate a token with Custom Scopes app:read and app:update and an expiry at https://cloud.digitalocean.com/account/api/tokens.', source: 'https://docs.digitalocean.com/reference/api/create-personal-access-token/' },
      { name: 'Custom-scope token with app:read', canReadValues: true, canWrite: false, scope: 'View App Platform apps, including GENERAL variable values; SECRET values are encrypted.', recommended: true,
        howToCreate: 'Generate a token with the Custom Scope app:read and an expiry at https://cloud.digitalocean.com/account/api/tokens.', source: 'https://docs.digitalocean.com/reference/api/scopes/' },
      { name: 'Read Only token', canReadValues: true, canWrite: false, scope: 'api:read: every read scope your team role allows.', recommended: false,
        howToCreate: 'Generate a Read Only token at https://cloud.digitalocean.com/account/api/tokens.', source: 'https://docs.digitalocean.com/reference/api/scopes/' },
      { name: 'Full Access token', canReadValues: true, canWrite: true, scope: 'api:write: every scope your team role allows, including deleting resources.', recommended: false,
        howToCreate: 'Generate a Full Access token at https://cloud.digitalocean.com/account/api/tokens.', source: 'https://docs.digitalocean.com/reference/api/scopes/' },
    ],
    keysentryUses: { scan: 'Read app specs: GENERAL values and SECRET names (SECRET values are encrypted).', rotate: 'Update selected variables in the app spec after approval; DigitalOcean deploys the app for every update.' },
  },
  'cloudflare-workers': {
    platform: 'Cloudflare Workers and Pages', source: 'https://developers.cloudflare.com/fundamentals/api/reference/permissions/',
    tokens: [
      { name: 'Account API token with Workers Scripts Read and Pages Read', canReadValues: true, canWrite: false, scope: 'One account; plain-text variables are readable, secret values never are.', recommended: true,
        howToCreate: 'Create an account API token in Manage account > Account API tokens at https://dash.cloudflare.com with Workers Scripts Read and Cloudflare Pages Read.', source: 'https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/' },
      { name: 'Account API token with Workers Scripts Edit and Pages Edit', canReadValues: true, canWrite: true, scope: 'One account; can write Worker secrets (each write deploys a new version) and Pages variables.', recommended: true,
        howToCreate: 'Create an account API token in Manage account > Account API tokens at https://dash.cloudflare.com with Workers Scripts Edit and Cloudflare Pages Edit.', source: 'https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/methods/update/' },
      { name: 'User API token with the same permissions', canReadValues: true, canWrite: true, scope: 'Acts for one person and inherits a subset of their permissions; stops working when they leave.', recommended: false,
        howToCreate: 'Create a token at https://dash.cloudflare.com/profile/api-tokens with Workers Scripts and Cloudflare Pages permissions.', source: 'https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/' },
      { name: 'Global API key', canReadValues: true, canWrite: true, scope: 'Every account of the user; keysentry does not accept it.', recommended: false,
        howToCreate: 'Not supported: use an API token instead. Details: https://developers.cloudflare.com/fundamentals/api/reference/permissions/', source: 'https://developers.cloudflare.com/fundamentals/api/reference/permissions/' },
    ],
    keysentryUses: { scan: 'List Workers and Pages projects, read plain-text variables and secret names.', rotate: 'Write Worker secrets (Cloudflare deploys each at once) and Pages variables after approval; Pages values apply on the next Pages deployment.' },
  },
  'supabase-functions': {
    platform: 'Supabase Edge Functions', source: 'https://supabase.com/docs/reference/api/introduction',
    tokens: [
      { name: 'Scoped personal access token with Edge Functions secrets read', canReadValues: false, canWrite: false, scope: 'Chosen organizations and projects; secret names only (FGA edge_functions_secrets_read, plus projects_read to list projects).', recommended: true,
        howToCreate: 'Create a scoped token at https://supabase.com/dashboard/account/tokens with the selected projects and Edge Functions secrets read.', source: 'https://supabase.com/docs/reference/api/v1-list-all-secrets' },
      { name: 'Scoped personal access token with Edge Functions secrets write', canReadValues: false, canWrite: true, scope: 'Chosen organizations and projects; can add or replace Edge Function secrets (FGA edge_functions_secrets_write).', recommended: true,
        howToCreate: 'Create a scoped token at https://supabase.com/dashboard/account/tokens with the selected projects and Edge Functions secrets write.', source: 'https://supabase.com/docs/reference/api/v1-bulk-create-secrets' },
      { name: 'Classic personal access token (Legacy)', canReadValues: false, canWrite: true, scope: 'Same privileges as your user account across every organization.', recommended: false,
        howToCreate: 'Avoid; create a scoped token at https://supabase.com/dashboard/account/tokens instead.', source: 'https://supabase.com/docs/reference/api/introduction' },
      { name: 'OAuth token with secrets:read / secrets:write', canReadValues: false, canWrite: true, scope: 'Scopes approved for an OAuth app by the organization; short-lived.', recommended: false,
        howToCreate: 'Approve the secrets and projects scopes for an OAuth app in your Supabase organization at https://supabase.com/dashboard.', source: 'https://supabase.com/docs/reference/api/introduction' },
    ],
    keysentryUses: { scan: 'List projects and Edge Function secret names; values are never read.', rotate: 'Add or replace selected secrets after approval; functions read them on their next invocation.' },
  },
  coolify: {
    platform: 'Coolify', source: 'https://coolify.io/docs/api/permissions',
    tokens: [
      { name: 'API token with read:sensitive', canReadValues: true, canWrite: false, scope: 'One team; includes read; the owner must be a team admin or owner.', recommended: true,
        howToCreate: 'In your Coolify instance open Keys & Tokens > API tokens, select the team and the read:sensitive permission. Details: https://coolify.io/docs/api/permissions', source: 'https://coolify.io/docs/api/permissions' },
      { name: 'API token with read:sensitive, write and deploy', canReadValues: true, canWrite: true, scope: 'One team; writes variables and triggers restarts or deployments.', recommended: true,
        howToCreate: 'In your Coolify instance open Keys & Tokens > API tokens and select read:sensitive, write and deploy. Details: https://coolify.io/docs/api/permissions', source: 'https://coolify.io/docs/api/permissions' },
      { name: 'API token with read only', canReadValues: false, canWrite: false, scope: 'One team; variable values stay redacted, so keysentry sees names only.', recommended: false,
        howToCreate: 'In your Coolify instance open Keys & Tokens > API tokens and select read. Details: https://coolify.io/docs/api/permissions', source: 'https://coolify.io/docs/api/permissions' },
      { name: 'API token with root', canReadValues: true, canWrite: true, scope: 'Bypasses read, write and deploy checks for one team.', recommended: false,
        howToCreate: 'Avoid; select explicit permissions in Keys & Tokens > API tokens instead. Details: https://coolify.io/docs/api/permissions', source: 'https://coolify.io/docs/api/permissions' },
    ],
    keysentryUses: { scan: 'List applications and services and read production variable values (read:sensitive).', rotate: 'Update selected variables and restart applications after approval.' },
  },
  zeabur: {
    platform: 'Zeabur', source: 'https://zeabur.com/docs/en-US/developer/api-keys',
    tokens: [
      { name: 'API key', canReadValues: true, canWrite: true, scope: 'Your personal account and the teams you belong to; no read-only or project-scoped key is documented.', recommended: true,
        howToCreate: 'Generate a key in Settings > API Keys at https://dash.zeabur.com.', source: 'https://zeabur.com/docs/en-US/developer/api-keys' },
    ],
    keysentryUses: { scan: 'List projects, environments and services and read variable values.', rotate: 'Replace the service variable set with the selected values changed, then restart the service after approval.' },
  },
  // Phase 5 secret stores (notes/secret-stores.md; docs read 2026-10-28).
  kubernetes: {
    platform: 'Kubernetes', source: 'https://kubernetes.io/docs/reference/access-authn-authz/authorization/',
    tokens: [
      { name: 'ServiceAccount token with a read Role', canReadValues: true, canWrite: false, scope: 'get and list on secrets in the configured namespaces; list returns full Secret data.', recommended: true,
        howToCreate: 'Create a ServiceAccount, a Role with get and list on secrets in each namespace and a RoleBinding, then issue a short-lived token with kubectl create token <name> --duration 1h. Details: https://kubernetes.io/docs/reference/access-authn-authz/rbac/', source: 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/' },
      { name: 'ServiceAccount token with a write Role', canReadValues: true, canWrite: true, scope: 'get, list and update on secrets in the configured namespaces; get and patch on deployments only when restarts are configured.', recommended: true,
        howToCreate: 'Bind a Role with get, list and update on secrets (and get, patch on the listed deployments) to a ServiceAccount, then run kubectl create token <name> --duration 1h. Details: https://kubernetes.io/docs/reference/access-authn-authz/authorization/', source: 'https://kubernetes.io/docs/reference/access-authn-authz/authorization/' },
      { name: 'Cluster-admin or personal kubeconfig token', canReadValues: true, canWrite: true, scope: 'Every Secret in the cluster.', recommended: false,
        howToCreate: 'Not recommended; use a namespaced ServiceAccount token instead. Details: https://kubernetes.io/docs/reference/access-authn-authz/rbac/', source: 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/' },
    ],
    keysentryUses: { scan: 'List and read Secrets in the configured namespaces.', rotate: 'Update selected Secret keys with a conditional write after approval; optionally restart the Deployments you listed.' },
  },
  'aws-secrets-manager': {
    platform: 'AWS Secrets Manager', source: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_iam-permissions.html',
    tokens: [
      { name: 'IAM access key with read permissions', canReadValues: true, canWrite: false, scope: 'secretsmanager:ListSecrets, DescribeSecret and GetSecretValue (plus kms:Decrypt for customer managed keys) on the secrets you choose.', recommended: true,
        howToCreate: 'Attach a policy with those actions to a dedicated IAM user or role at https://console.aws.amazon.com/iam/ and create its access key.', source: 'https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html' },
      { name: 'IAM access key with write permissions', canReadValues: true, canWrite: true, scope: 'Read permissions plus secretsmanager:PutSecretValue and UpdateSecretVersionStage (plus kms:GenerateDataKey for customer managed keys).', recommended: true,
        howToCreate: 'Attach the read and write actions, scoped to the secret ARNs, to a dedicated IAM principal at https://console.aws.amazon.com/iam/.', source: 'https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_UpdateSecretVersionStage.html' },
      { name: 'Temporary role credentials', canReadValues: true, canWrite: true, scope: 'Whatever the assumed role allows; include the session token.', recommended: false,
        howToCreate: 'Assume a role with the permissions above and provide all three values. Details: https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html', source: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html' },
    ],
    keysentryUses: { scan: 'List secrets and read their current values in the configured region.', rotate: 'Create a new version and make it current only if the secret did not change meanwhile, after approval.' },
  },
  'vault-kv': {
    platform: 'HashiCorp Vault (KV v2)', source: 'https://developer.hashicorp.com/vault/docs/concepts/policies',
    tokens: [
      { name: 'Token with a read policy', canReadValues: true, canWrite: false, scope: 'read on <mount>/data/<paths>* and list on <mount>/metadata/<paths>*.', recommended: true,
        howToCreate: 'Write a policy with those paths and create a token with it (vault token create -policy=<name> -ttl=1h). Details: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2', source: 'https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2' },
      { name: 'Token with a write policy', canReadValues: true, canWrite: true, scope: 'Read policy plus patch (preferred) or update on <mount>/data/<paths>*.', recommended: true,
        howToCreate: 'Add patch (or create and update) on the data paths to a separate policy used only for rotation. Details: https://developer.hashicorp.com/vault/docs/concepts/policies', source: 'https://developer.hashicorp.com/vault/docs/concepts/policies' },
      { name: 'Root token', canReadValues: true, canWrite: true, scope: 'Everything in Vault.', recommended: false,
        howToCreate: 'Not recommended; use a scoped policy token. Details: https://developer.hashicorp.com/vault/docs/concepts/policies', source: 'https://developer.hashicorp.com/vault/docs/concepts/policies' },
    ],
    keysentryUses: { scan: 'List KV paths and read string values under the configured paths.', rotate: 'Patch only the selected keys with check-and-set after approval.' },
  },
  doppler: {
    platform: 'Doppler', source: 'https://docs.doppler.com/reference/api',
    tokens: [
      { name: 'Service token (read)', canReadValues: true, canWrite: false, scope: 'Secrets of one config; restricted values are returned to it.', recommended: true,
        howToCreate: 'Create a read-only service token for the config at https://dashboard.doppler.com and list that project/config in hosts.doppler.configs.', source: 'https://docs.doppler.com/docs/service-tokens' },
      { name: 'Service token (read/write)', canReadValues: true, canWrite: true, scope: 'Read and write secrets of one config.', recommended: true,
        howToCreate: 'Create a service token with write access for the config at https://dashboard.doppler.com.', source: 'https://docs.doppler.com/reference/api' },
      { name: 'Service account token', canReadValues: true, canWrite: true, scope: 'The projects, environments and role granted to the service account.', recommended: false,
        howToCreate: 'Create a service account, grant project access, and create a token at https://dashboard.doppler.com.', source: 'https://docs.doppler.com/docs/service-accounts' },
      { name: 'Personal or CLI token', canReadValues: true, canWrite: true, scope: 'All resources on your account; restricted values are not returned.', recommended: false,
        howToCreate: 'Not recommended for keysentry; use a service token. Details: https://docs.doppler.com/docs/secret-visibility', source: 'https://docs.doppler.com/docs/secret-visibility' },
    ],
    keysentryUses: { scan: 'List root configs and read raw secret values.', rotate: 'Update selected secrets with a current-value precondition after approval.' },
  },
  infisical: {
    platform: 'Infisical', source: 'https://infisical.com/docs/api-reference/overview/authentication',
    tokens: [
      { name: 'Machine identity with the Viewer role', canReadValues: true, canWrite: false, scope: 'Read-only access to the project\'s secrets in the environments it is granted.', recommended: true,
        howToCreate: 'Create a machine identity with Universal Auth at https://app.infisical.com, add it to the project with the Viewer role, and store its client ID and secret.', source: 'https://infisical.com/docs/documentation/platform/access-controls/role-based-access-controls' },
      { name: 'Machine identity with the Member role', canReadValues: true, canWrite: true, scope: 'Read and write secrets in all environments of the project.', recommended: true,
        howToCreate: 'Add a separate machine identity to the project with the Member role (or a custom role limited to the paths keysentry rotates). Details: https://infisical.com/docs/documentation/platform/access-controls/role-based-access-controls', source: 'https://infisical.com/docs/documentation/platform/access-controls/role-based-access-controls' },
      { name: 'Service token', canReadValues: true, canWrite: true, scope: 'Selected environments and paths with read and/or write; legacy token type.', recommended: false,
        howToCreate: 'Prefer a machine identity; service tokens are created in the project settings. Details: https://infisical.com/docs/documentation/platform/token', source: 'https://infisical.com/docs/documentation/platform/token' },
    ],
    keysentryUses: { scan: 'List folders and read shared secret values in the configured environments.', rotate: 'Bulk-update or create the selected secrets after approval; changes behind an approval policy wait for that approval.' },
  },
  // Phase 6 providers (notes/providers-a.md, notes/providers-b.md; docs read 2026-10-28).
  google: {
    platform: 'Google Cloud API keys', source: 'https://docs.cloud.google.com/api-keys/docs/access-control',
    tokens: [
      { name: 'Service-account key with API Keys Admin', canReadValues: true, canWrite: true,
        scope: 'API keys of the project where the role is granted: list, read key strings, create, update, delete and restore. Keys bound to a service account also need Service Account User and Service Account API Key Binding Admin.',
        recommended: true,
        howToCreate: 'Create a service account, grant it API Keys Admin (roles/serviceusage.apiKeysAdmin) on the project, and add a JSON key at https://console.cloud.google.com/iam-admin/serviceaccounts.',
        source: 'https://docs.cloud.google.com/api-keys/docs/access-control' },
      { name: 'OAuth access token (cloud-platform scope)', canReadValues: true, canWrite: true,
        scope: 'Whatever the signed-in principal may do; expires after about an hour, so it suits one interactive rotation, not a watcher.',
        recommended: false,
        howToCreate: 'Run gcloud auth print-access-token as a principal with API Keys Admin on the project (https://console.cloud.google.com/iam-admin/iam).',
        source: 'https://docs.cloud.google.com/api-keys/docs/create-manage-api-keys' },
      { name: 'Service-account key with API Keys Viewer', canReadValues: true, canWrite: false,
        scope: 'Read key metadata and key strings of one project; enough to identify keys, not to rotate them.',
        recommended: false,
        howToCreate: 'Grant roles/serviceusage.apiKeysViewer to a service account and add a JSON key at https://console.cloud.google.com/iam-admin/serviceaccounts.',
        source: 'https://docs.cloud.google.com/api-keys/docs/access-control' },
    ],
    keysentryUses: {
      scan: 'Read key metadata and key strings in the configured project to identify which key a deployed value is; values stay in memory.',
      rotate: 'Create a replacement with the same restrictions, annotations and bound service account, then delete the old key after approval (restorable for 30 days). Service-account JSON keys stay guided.',
    },
  },
  groq: {
    platform: 'Groq', source: 'https://console.groq.com/docs/api-reference',
    tokens: [
      { name: 'API key', canReadValues: false, canWrite: false,
        scope: 'Inference API for its organization; the API documents no key-management endpoints.', recommended: false,
        howToCreate: 'Create it at https://console.groq.com/keys.', source: 'https://console.groq.com/docs/api-reference' },
    ],
    keysentryUses: { scan: 'Verify a deployed key by listing models.', rotate: 'Guide you to create a replacement and delete the old key in the Groq console.' },
  },
  mistral: {
    platform: 'Mistral', source: 'https://docs.mistral.ai/admin/admin-api/authentication',
    tokens: [
      { name: 'Admin API key', canReadValues: false, canWrite: true,
        scope: 'One Organization\'s admin endpoints (users, Workspaces, API keys, limits, usage, audit logs); Enterprise plans only, preview API.',
        recommended: true,
        howToCreate: 'An Enterprise account admin creates it in the Mistral Admin Panel under API keys; a Workspace API key from https://console.mistral.ai/api-keys never grants admin access.',
        source: 'https://docs.mistral.ai/admin/admin-api/authentication' },
      { name: 'Workspace API key', canReadValues: false, canWrite: false,
        scope: 'Model and Connector access within one Workspace.', recommended: false,
        howToCreate: 'Create it at https://console.mistral.ai/api-keys.', source: 'https://docs.mistral.ai/admin/identity-access/api-keys' },
    ],
    keysentryUses: { scan: 'List masked key hints to identify a deployed key.', rotate: 'Guide you to create the replacement, then delete the identified old key after approval.' },
  },
  replicate: {
    platform: 'Replicate', source: 'https://replicate.com/docs/reference/http',
    tokens: [
      { name: 'API token', canReadValues: false, canWrite: false,
        scope: 'The user or organization account it belongs to (predictions, models, deployments); no token-management endpoints are documented.',
        recommended: false, howToCreate: 'Create it at https://replicate.com/account/api-tokens.', source: 'https://replicate.com/docs/reference/http' },
    ],
    keysentryUses: { scan: 'Verify a deployed token by reading its account.', rotate: 'Guide you to create a replacement and delete the old token on the API tokens page.' },
  },
  clerk: {
    platform: 'Clerk', source: 'https://clerk.com/docs/guides/secure/rotate-api-keys',
    tokens: [
      { name: 'Secret key (sk_live_/sk_test_)', canReadValues: false, canWrite: false,
        scope: 'Full Backend API access to one instance (users, sessions, organizations); optionally IP-restricted; cannot manage secret keys.',
        recommended: false, howToCreate: 'Add it under API keys > Secret keys at https://dashboard.clerk.com/last-active?path=api-keys.',
        source: 'https://clerk.com/docs/guides/secure/rotate-api-keys' },
      { name: 'Platform API access token', canReadValues: true, canWrite: true,
        scope: 'Workspace-level management (private beta); its rotation replaces every secret key of an instance, so keysentry does not use it.',
        recommended: false, howToCreate: 'Request Platform API access for the workspace from Clerk. Details: https://github.com/clerk/openapi-specs/blob/main/platform/beta.yml',
        source: 'https://github.com/clerk/openapi-specs/blob/main/platform/beta.yml' },
    ],
    keysentryUses: { scan: 'Verify a deployed secret key by reading the instance JWKS.', rotate: 'Guide you to add a replacement secret key, redeploy, and delete the old key in the Dashboard.' },
  },
  twilio: {
    platform: 'Twilio', source: 'https://www.twilio.com/docs/iam/api-keys',
    tokens: [
      { name: 'Main API key', canReadValues: false, canWrite: true, scope: 'Full access to every Twilio resource, equivalent to the Account SID and Auth Token, including creating and deleting API keys.', recommended: true,
        howToCreate: 'Create a Main API key at https://console.twilio.com/us1/account/keys-credentials/api-keys; Main keys cannot be created through the API.', source: 'https://www.twilio.com/docs/iam/api-keys' },
      { name: 'Account SID and Auth Token', canReadValues: false, canWrite: true, scope: 'The account root credential; can manage API keys and rotate the Auth Token itself.', recommended: false,
        howToCreate: 'Copy the Account SID and Auth Token from https://console.twilio.com.', source: 'https://www.twilio.com/docs/usage/requests-to-twilio' },
      { name: 'Restricted API key', canReadValues: false, canWrite: false, scope: 'Only the permissions in its policy; /twilio/iam/api-keys/create allows creating keys, but the permissions for reading and deleting keys are not documented.', recommended: false,
        howToCreate: 'Create a Restricted key at https://console.twilio.com/us1/account/keys-credentials/api-keys.', source: 'https://www.twilio.com/docs/iam/api-keys/key-resource-v1' },
      { name: 'Standard API key', canReadValues: false, canWrite: false, scope: 'Every resource except Accounts and Keys; cannot manage API keys.', recommended: false,
        howToCreate: 'Create a Standard key at https://console.twilio.com/us1/account/keys-credentials/api-keys.', source: 'https://www.twilio.com/docs/iam/api-keys' },
    ],
    keysentryUses: { scan: 'Verify a key pair or Auth Token with a one-item Applications list.', rotate: 'Create a Standard or Restricted replacement with the same policy, deliver the new SID with its secret, and delete the old key after approval. Auth Tokens and Main keys stay guided.' },
  },
  sendgrid: {
    platform: 'SendGrid', source: 'https://www.twilio.com/docs/sendgrid/api-reference/api-keys/create-api-keys',
    tokens: [
      { name: 'Full Access API key', canReadValues: false, canWrite: true, scope: 'Every endpoint except billing and Email Address Validation, including API key management, in one account or subuser.', recommended: true,
        howToCreate: 'Create a Full Access API key at https://app.sendgrid.com/settings/api_keys.', source: 'https://www.twilio.com/docs/sendgrid/api-reference/api-keys/create-api-keys' },
      { name: 'Restricted key with API Keys permissions', canReadValues: false, canWrite: true, scope: 'api_keys.create, api_keys.read and api_keys.delete; whether it may grant scopes it does not hold is not documented, so replacements with other scopes may be refused.', recommended: false,
        howToCreate: 'Create a Restricted Access key with API Keys permissions at https://app.sendgrid.com/settings/api_keys.', source: 'https://www.twilio.com/docs/sendgrid/api-reference/api-key-permissions' },
      { name: 'Mail Send key', canReadValues: false, canWrite: false, scope: 'Send mail only; cannot manage keys.', recommended: false,
        howToCreate: 'Create a Restricted Access key with Mail Send at https://app.sendgrid.com/settings/api_keys.', source: 'https://www.twilio.com/docs/sendgrid/api-reference/api-key-permissions' },
    ],
    keysentryUses: { scan: 'Verify a key through its own scope list.', rotate: 'Create a replacement with the old key\'s exact scopes in the same account, then delete the old key after approval.' },
  },
  postmark: {
    platform: 'Postmark', source: 'https://postmarkapp.com/developer/api/overview',
    tokens: [
      { name: 'Server API token', canReadValues: false, canWrite: false, scope: 'One server\'s sending and data endpoints; no API creates or deletes tokens.', recommended: false,
        howToCreate: 'Generate a token in the server\'s API Tokens tab at https://account.postmarkapp.com/servers.', source: 'https://postmarkapp.com/support/article/1293-how-to-cycle-a-server-api-token' },
      { name: 'Account API token', canReadValues: true, canWrite: false, scope: 'Account-level endpoints; server responses include every server API token. No API creates or deletes tokens.', recommended: false,
        howToCreate: 'Generate another account token (at most three) under Account > API Tokens at https://account.postmarkapp.com.', source: 'https://postmarkapp.com/support/article/1212-can-you-have-more-than-one-account-api-token-at-a-time' },
    ],
    keysentryUses: { scan: 'Verify a token with a read that returns no tokens (delivery stats or the domain list).', rotate: 'Guided only: Postmark has no API to create or delete tokens.' },
  },
  neon: {
    platform: 'Neon', source: 'https://neon.com/docs/manage/api-keys',
    tokens: [
      { name: 'Personal API key', canReadValues: false, canWrite: true, scope: 'Every project its user can access; can create and revoke that user\'s personal keys.', recommended: true,
        howToCreate: 'Create a personal API key at https://console.neon.tech/app/settings/api-keys.', source: 'https://neon.com/docs/manage/api-keys' },
      { name: 'Organization API key', canReadValues: false, canWrite: false, scope: 'All projects of one organization; keysentry does not rotate organization keys automatically.', recommended: false,
        howToCreate: 'An organization admin creates it in the organization settings at https://console.neon.tech.', source: 'https://neon.com/docs/manage/api-keys' },
      { name: 'Project-scoped API key', canReadValues: false, canWrite: false, scope: 'One project with Editor access; cannot manage keys or the organization.', recommended: false,
        howToCreate: 'An organization admin creates it for one project at https://console.neon.tech.', source: 'https://neon.com/docs/manage/api-keys' },
    ],
    keysentryUses: { scan: 'Verify a key through the auth details endpoint.', rotate: 'Create a personal key for the same user after approval; delete the old key by hand because Neon exposes no value hints. Connection-string passwords stay guided.' },
  },
  upstash: {
    platform: 'Upstash', source: 'https://upstash.com/docs/devops/developer-api/introduction',
    tokens: [
      { name: 'Developer API key (Read/Write)', canReadValues: true, canWrite: true, scope: 'Every database and QStash user of the account, including their passwords and tokens; native Upstash accounts only (not accounts created through Vercel or Fly).', recommended: true,
        howToCreate: 'Create a key with Read/Write permission and an expiry under Account > Developer API at https://console.upstash.com.', source: 'https://upstash.com/docs/devops/developer-api/introduction' },
      { name: 'Developer API key (Read Only)', canReadValues: false, canWrite: false, scope: 'Hides database passwords and REST tokens; cannot reset credentials.', recommended: false,
        howToCreate: 'Create a Read Only key under Account > Developer API at https://console.upstash.com.', source: 'https://upstash.com/docs/devops/developer-api/redis/get_database.md' },
    ],
    keysentryUses: { scan: 'Verify REST tokens with PING and QStash tokens with a queue list.', rotate: 'After approval, reset the database password or QStash token; the old credential stops working at once.' },
  },
};
