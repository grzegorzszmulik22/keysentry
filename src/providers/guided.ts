import type { Guidance, ProviderAdapter, ProviderContext, VerifyResult } from '../types.js';
import { readJson, request, safeIdentity, verifyRead } from './shared.js';

export type GuidedProviderId = 'slack' | 'sendgrid' | 'twilio' | 'google' | 'private-key' | 'crypto-wallet' | 'unknown';

const guidance: Record<GuidedProviderId, Guidance> = {
  slack: {
    url: 'https://api.slack.com/apps',
    steps: [
      'Open the issuing Slack app and replace or rotate its OAuth token; for an incoming webhook, create a replacement webhook instead.',
      'Update every consumer and redeploy, then verify the token or send a controlled test through the replacement webhook.',
      'Revoke the old token or delete the old webhook after the replacement works everywhere.',
    ],
  },
  sendgrid: {
    url: 'https://app.sendgrid.com/settings/api_keys',
    steps: [
      'Create a replacement API key in SendGrid with only the permissions needed by its consumers.',
      'Update every consumer and redeploy, verify the key and application mail delivery, then delete the old API key.',
    ],
  },
  twilio: {
    url: 'https://console.twilio.com/',
    steps: [
      'For an account Auth Token, use the Twilio console secondary Auth Token rotation flow; for an API key, create a replacement API key and secret.',
      'Update the matching account or API key identifier together with its secret in every consumer and redeploy.',
      'Verify the affected API calls before promoting the secondary Auth Token or deleting the old API key.',
    ],
  },
  google: {
    url: 'https://console.cloud.google.com/apis/credentials',
    steps: [
      'Create a replacement API key in Google Cloud credentials, or create a new JSON key for the service account in IAM; preserve required API and application restrictions.',
      'For a service-account key, replace the full credential document including its private key and key identifier.',
      'Update every consumer and redeploy, verify the affected Google API calls, then delete the exposed old key.',
    ],
  },
  'private-key': {
    url: 'https://www.openssh.com/manual.html',
    steps: [
      'Generate a new private/public key pair with the tool appropriate to its use, keeping the private key in the authorized secret store.',
      'Install the replacement public key or certificate in every verifier and update the private key in every consumer.',
      'Test authentication or signature verification, then remove trust in the old public key and revoke any affected certificates.',
    ],
  },
  'crypto-wallet': {
    url: 'https://ethereum.org/en/security/',
    steps: [
      'Move funds to a new wallet first; rotating the variable does not protect funds already exposed.',
      'Create the new wallet using a trusted wallet tool, secure its recovery material, and transfer funds and token permissions from the exposed wallet.',
      'Update consumers to use the new wallet only after checking its address and required permissions; retire the exposed private key or seed permanently.',
    ],
  },
  unknown: {
    url: 'https://owasp.org/www-project-cheat-sheets/',
    steps: [
      'Identify the service that issued this credential and open its official credential management page.',
      'Create a replacement with the required permissions, update every consumer, and redeploy.',
      'Verify real application access before revoking the exposed old credential at its issuer.',
    ],
  },
};

async function verifySlack(value: string, ctx: ProviderContext): Promise<VerifyResult> {
  if (!value.startsWith('xox')) return { ok: true, identity: 'unverified' };
  const response = await request(ctx, {
    method: 'POST',
    url: 'https://slack.com/api/auth.test',
    headers: { Authorization: `Bearer ${value}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: '',
  }, 'Slack');
  if (response.status < 200 || response.status >= 300) {
    return { ok: false, status: response.status, error: 'Slack authentication failed.' };
  }
  let data: unknown;
  try {
    data = readJson<unknown>(response, 'Slack');
  } catch {
    return { ok: false, status: response.status, error: 'Slack returned an invalid authentication response.' };
  }
  if (!data || typeof data !== 'object' || (data as Record<string, unknown>).ok !== true) {
    return { ok: false, status: response.status, error: 'Slack authentication failed.' };
  }
  return {
    ok: true,
    status: response.status,
    identity: safeIdentity((data as Record<string, unknown>).user, 'Slack account', [
      value,
      ...Object.values(ctx.credentials).filter((credential): credential is string => typeof credential === 'string'),
    ]),
  };
}

export function createGuidedAdapter(id: GuidedProviderId): ProviderAdapter {
  return {
    id,
    method: 'guided',
    async verify(value, ctx) {
      if (id === 'slack') return verifySlack(value, ctx);
      if (id === 'sendgrid') {
        return verifyRead(ctx, {
          method: 'GET',
          url: 'https://api.sendgrid.com/v3/scopes',
          headers: { Authorization: `Bearer ${value}` },
        }, 'SendGrid', () => 'SendGrid account');
      }
      return { ok: true, identity: 'unverified' };
    },
    guidance() {
      return { url: guidance[id].url, steps: [...guidance[id].steps] };
    },
  };
}

export const slackProvider = createGuidedAdapter('slack');
export const sendgridProvider = createGuidedAdapter('sendgrid');
export const twilioProvider = createGuidedAdapter('twilio');
export const googleProvider = createGuidedAdapter('google');
export const privateKeyProvider = createGuidedAdapter('private-key');
export const cryptoWalletProvider = createGuidedAdapter('crypto-wallet');
export const unknownProvider = createGuidedAdapter('unknown');
