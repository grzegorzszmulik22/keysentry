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
};
