import type { ProviderAdapter } from '../types.js';
import { verifyRead } from './shared.js';

function projectOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    const loopback = url.hostname === 'localhost' || url.hostname === '[::1]' || /^127(?:\.\d{1,3}){3}$/.test(url.hostname);
    if (value !== value.trim() || /[?#]/.test(value) || url.username || url.password || url.pathname !== '/') return null;
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

export const supabaseProvider: ProviderAdapter = {
  id: 'supabase',
  method: 'guided',
  async verify(value, ctx) {
    const configured = ctx.siblingVars?.SUPABASE_URL;
    if (!configured) return { ok: true, identity: 'unverified' };
    const origin = projectOrigin(configured);
    if (!origin) return { ok: false, error: 'Supabase verification requires an HTTPS project origin or a local HTTP origin without credentials, query, or fragment.' };
    return verifyRead(ctx, {
      method: 'GET',
      url: `${origin}/rest/v1/`,
      headers: { apikey: value, Authorization: `Bearer ${value}` },
    }, 'Supabase', () => 'Supabase project');
  },
  guidance() {
    return {
      url: 'https://supabase.com/dashboard',
      steps: [
        'Open the project settings and API keys page; create a replacement secret key with the required access.',
        'For a legacy service-role JWT, follow the project JWT signing secret rotation procedure: rotating that signing secret can affect other JWT keys and active sessions.',
        'Update every consumer and redeploy, verify access against the matching SUPABASE_URL, then revoke the old key or complete the signing secret rotation.',
      ],
    };
  },
};
