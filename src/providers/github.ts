import type { ProviderAdapter } from '../types.js';
import { safeIdentity, verifyRead } from './shared.js';

export const githubProvider: ProviderAdapter = {
  id: 'github',
  method: 'guided',
  verify(value, ctx) {
    return verifyRead(ctx, {
      method: 'GET',
      url: 'https://api.github.com/user',
      headers: {
        Authorization: `Bearer ${value}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'keysentry',
      },
    }, 'GitHub', (data) => safeIdentity(
      data && typeof data === 'object' ? (data as Record<string, unknown>).login : undefined,
      'GitHub account',
      [value],
    ));
  },
  guidance() {
    return {
      url: 'https://github.com/settings/tokens',
      steps: [
        'Create a replacement personal access token with the required repositories, permissions, and expiry; obtain organization approval if required.',
        'For an app or OAuth token, create the replacement through its issuing app instead of the personal access token page.',
        'Update every consumer and rerun the affected workflows or redeploy services, then revoke the old token after verification.',
      ],
    };
  },
};
