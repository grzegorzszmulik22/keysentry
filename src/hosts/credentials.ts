import type { HostId } from '../types.js';

/**
 * Vault credential names each host adapter reads, in the order they are tried. Names in one list are alternatives,
 * except the AWS Secrets Manager access key pair (plus its optional session token) and Infisical's Universal Auth
 * client id and secret, which belong together. Used by `vault set`, doctor, the dashboard platforms screen and the
 * watcher deployment export.
 */
export const HOST_CREDENTIALS: Readonly<Record<HostId, readonly string[]>> = {
  railway: ['RAILWAY_TOKEN', 'RAILWAY_PROJECT_TOKEN'],
  vercel: ['VERCEL_TOKEN'],
  render: ['RENDER_API_KEY'],
  fly: ['FLY_API_TOKEN'],
  'github-actions': ['GITHUB_TOKEN'],
  dotenv: [],
  netlify: ['NETLIFY_TOKEN'],
  heroku: ['HEROKU_API_KEY'],
  digitalocean: ['DIGITALOCEAN_TOKEN'],
  // Distinct from the Cloudflare provider's CLOUDFLARE_ADMIN_TOKEN and from app keys named CLOUDFLARE_API_TOKEN.
  'cloudflare-workers': ['CLOUDFLARE_WORKERS_TOKEN'],
  // Distinct from a classic SUPABASE_ACCESS_TOKEN in the developer's shell.
  'supabase-functions': ['SUPABASE_FUNCTIONS_TOKEN'],
  coolify: ['COOLIFY_TOKEN'],
  zeabur: ['ZEABUR_TOKEN'],
  kubernetes: ['KUBERNETES_TOKEN'],
  // A dedicated prefix so a broad developer profile in AWS_ACCESS_KEY_ID is never picked up by accident.
  'aws-secrets-manager': ['AWS_SECRETS_MANAGER_ACCESS_KEY_ID', 'AWS_SECRETS_MANAGER_SECRET_ACCESS_KEY', 'AWS_SECRETS_MANAGER_SESSION_TOKEN'],
  'vault-kv': ['VAULT_TOKEN'],
  doppler: ['DOPPLER_TOKEN'],
  infisical: ['INFISICAL_TOKEN', 'INFISICAL_CLIENT_ID', 'INFISICAL_CLIENT_SECRET'],
};
