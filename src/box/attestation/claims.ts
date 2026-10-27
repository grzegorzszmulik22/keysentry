import type { AttestationPolicy, AttestationResult } from '../../types.js';

export const CONFIDENTIAL_SPACE_ISSUER = 'https://confidentialcomputing.googleapis.com';
export type AttestationCheck = AttestationResult['checks'][number];

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

function strings(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function nonce(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) &&
    Buffer.from(value, 'base64url').toString('base64url') === value;
}

function dateSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** The first expected nonce binds the box key; the second is the CLI challenge. */
export function checkClaims(
  value: unknown, policy: AttestationPolicy, expectedNonces: string[], now: Date,
): AttestationCheck[] {
  const claims = record(value);
  const submods = record(claims.submods);
  const container = record(submods.container);
  const space = record(submods.confidential_space);
  const gce = record(submods.gce);
  const checks: AttestationCheck[] = [];
  function add(name: string, ok: boolean, pass: string, fail: string): void {
    checks.push({ name, ok, detail: ok ? pass : fail });
  }

  add('issuer', claims.iss === CONFIDENTIAL_SPACE_ISSUER,
    'Confidential Space issuer matches.', 'Confidential Space issuer does not match.');
  const audience = typeof claims.aud === 'string' ? claims.aud === policy.audience :
    strings(claims.aud) && claims.aud.includes(policy.audience);
  add('audience', audience && typeof policy.audience === 'string' && policy.audience.length > 0,
    'Requested audience matches.', 'Requested audience does not match.');

  const seconds = now.getTime() / 1000;
  const skew = policy.clockSkewSeconds ?? 60;
  const maxAge = policy.maxTokenAgeSeconds ?? 300;
  const { exp, iat, nbf } = claims;
  const time = Number.isFinite(seconds) && Number.isFinite(skew) && skew >= 0 &&
    Number.isFinite(maxAge) && maxAge >= 0 && dateSeconds(exp) && dateSeconds(iat) &&
    (nbf === undefined || dateSeconds(nbf)) && iat <= seconds + skew &&
    (nbf === undefined || nbf <= seconds + skew) && exp >= seconds - skew &&
    seconds - iat <= maxAge && exp >= iat && (nbf === undefined || nbf <= exp);
  add('time', time, 'Token is current and recently issued.', 'Token time or freshness is outside the allowed window.');

  const expectedValid = Array.isArray(expectedNonces) && expectedNonces.length === 2 &&
    expectedNonces.every(nonce) && new Set(expectedNonces).size === 2;
  const observed = typeof claims.eat_nonce === 'string' ? [claims.eat_nonce] : claims.eat_nonce;
  const observedValid = strings(observed);
  const nonceSet = new Set(observedValid ? observed : []);
  add('nonce-box-key', expectedValid && observedValid && nonceSet.has(expectedNonces[0]!),
    'Nonce binds the expected box key.', 'Nonce does not bind the expected box key.');
  add('nonce-challenge', expectedValid && observedValid && nonceSet.has(expectedNonces[1]!),
    'Fresh CLI challenge matches.', 'Fresh CLI challenge does not match.');
  add('nonce-set', expectedValid && observedValid && nonceSet.size === 2 &&
    expectedNonces.every((entry) => nonceSet.has(entry)),
    'Token nonce set matches the session.', 'Token nonce set differs from the session.');

  add('secure-boot', claims.secboot === true, 'Secure boot is enabled.', 'Secure boot is not confirmed.');
  add('debug', claims.dbgstat === 'disabled-since-boot',
    'Debugging has been disabled since boot.', 'Production debugging status is not confirmed.');
  add('software', claims.swname === 'CONFIDENTIAL_SPACE',
    'Confidential Space software matches.', 'Confidential Space software does not match.');
  const hardware = claims.hwmodel;
  add('hardware', (hardware === 'GCP_INTEL_TDX' || hardware === 'GCP_AMD_SEV') &&
    policy.hardwareModels.includes(hardware),
    'Hardware model is permitted.', 'Hardware model is not permitted.');
  add('support-stable', strings(space.support_attributes) && space.support_attributes.includes('STABLE'),
    'Production image has STABLE support.', 'Production image lacks STABLE support.');

  const monitoring = record(space.monitoring_enabled);
  const memory = monitoring.memory;
  const monitoringShape = space.monitoring_enabled === undefined ||
    (space.monitoring_enabled !== null && typeof space.monitoring_enabled === 'object' && !Array.isArray(space.monitoring_enabled));
  add('memory-monitoring', monitoringShape && (memory === undefined || memory === false),
    'Memory monitoring is not enabled.', 'Memory monitoring is enabled or its setting is invalid.');
  add('image-digest', typeof container.image_digest === 'string' &&
    /^sha256:[a-f0-9]{64}$/.test(container.image_digest) && policy.allowedDigests.includes(container.image_digest),
    'Image digest is in the verified allow-list.', 'Image digest is not in the verified allow-list.');

  const env = container.env_override;
  const noEnv = env === undefined || (env !== null && typeof env === 'object' && !Array.isArray(env) && Object.keys(env).length === 0);
  add('env-override', noEnv, 'No environment override is present.', 'Environment overrides are present or invalid.');
  const cmd = container.cmd_override;
  add('cmd-override', cmd === undefined || (Array.isArray(cmd) && cmd.length === 0),
    'No command override is present.', 'Command overrides are present or invalid.');
  add('project', typeof gce.project_id === 'string' && policy.projectIds.includes(gce.project_id),
    'Box project is permitted.', 'Box project is not permitted.');
  add('service-account', strings(claims.google_service_accounts) && claims.google_service_accounts.length > 0 &&
    claims.google_service_accounts.every((account) => policy.serviceAccounts.includes(account)),
    'Box service accounts are permitted.', 'Box service accounts are missing or not permitted.');
  return checks;
}
