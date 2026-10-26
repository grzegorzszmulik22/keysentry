import type { ProviderAdapter } from '../types.js';

export const databaseProvider: ProviderAdapter = {
  id: 'database',
  method: 'guided',
  async verify() {
    return { ok: true, identity: 'unverified' };
  },
  guidance() {
    return {
      url: 'https://railway.com/dashboard',
      steps: [
        'Change the password at the database first; changing only the connection variable does not rotate the database credential.',
        'Use the Railway Database tab and Regenerate, the Neon or Supabase database dashboard, or your database administrator password-change command such as ALTER USER ... PASSWORD.',
        'If supported, create a replacement database role first to preserve overlap; keep its privileges limited to the application requirements.',
        'Update the connection URL everywhere and redeploy, then test a real database connection before disabling an overlapping old credential.',
      ],
    };
  },
};
