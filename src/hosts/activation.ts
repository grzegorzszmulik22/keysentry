import type { ActivationMode, HostAdapter, ServiceRef } from '../types.js';

export type { ActivationMode } from '../types.js';

type ServiceShape = Pick<ServiceRef, 'host' | 'serviceId' | 'environmentId'>;

/**
 * How each built-in host applies new values, for callers that know a service only by its host id (the readiness
 * score) and for adapters that declare nothing. Every built-in adapter declares the same through
 * `capabilities.activation` or `activationFor`, which take precedence.
 */
export function builtInActivation(service: ServiceShape): ActivationMode {
  switch (service.host) {
    // A Railway shared variable activates through the services that reference it; the engine follows those
    // references, so on its own it cannot be confirmed.
    case 'railway': return service.serviceId === '' ? 'manual' : 'redeploy';
    case 'vercel': return service.environmentId === 'production' ? 'redeploy' : 'manual';
    case 'render': return 'redeploy';
    // Fly restarts machines without a deployment keysentry can confirm before writing.
    case 'fly': case 'github-actions': case 'dotenv': return 'manual';
    // Only the production context of a site is rebuilt; previews, branch deploys and shared team variables apply on
    // their next deploy.
    case 'netlify': return service.environmentId === 'production' && service.serviceId !== '' ? 'redeploy' : 'manual';
    case 'heroku': case 'digitalocean': return 'on-write';
    // Each Worker secret write deploys a new version; Pages values apply on the next Pages deployment.
    case 'cloudflare-workers': return service.serviceId.startsWith('worker:') ? 'on-write' : 'manual';
    case 'supabase-functions': return 'immediate';
    // Coolify applications return a deployment id for their restart; services do not.
    case 'coolify': return service.serviceId.startsWith('application:') ? 'redeploy' : 'manual';
    // Zeabur restarts return no deployment id.
    case 'zeabur': return 'manual';
    // Secret stores do not deploy. Whether consumers read at use time is up to the application (see the README).
    case 'kubernetes': case 'aws-secrets-manager': case 'vault-kv': case 'doppler': case 'infisical': return 'manual';
  }
}

/** The one place that decides how a service's new values take effect. */
export function activationMode(service: ServiceShape & Partial<ServiceRef>, host?: Pick<HostAdapter, 'capabilities' | 'activationFor'>): ActivationMode {
  if (host) {
    const declared = host.activationFor?.(service as ServiceRef) ?? host.capabilities.activation;
    // A deploy-confirming mode needs a deploy step; an adapter without one cannot confirm a redeploy.
    if (declared) return declared === 'redeploy' && !host.capabilities.redeploy ? 'manual' : declared;
    if (!host.capabilities.redeploy) return 'manual';
  }
  return builtInActivation(service);
}

/**
 * Whether keysentry can confirm that a written service runs the new values. `redeployEnabled: false` (rotate
 * --no-redeploy) leaves `redeploy` hosts to the operator; `on-write` hosts deploy with the write anyway, so their
 * deployment is still confirmed, and `immediate` hosts need no deployment.
 */
export function canConfirmActivation(mode: ActivationMode, redeployEnabled = true): boolean {
  return mode === 'immediate' || mode === 'on-write' || (mode === 'redeploy' && redeployEnabled);
}

/** Manual restart or next-deploy activation needed for this service. */
export function needsManualActivation(service: ServiceShape & Partial<ServiceRef>, host?: Pick<HostAdapter, 'capabilities' | 'activationFor'>, redeployEnabled = true): boolean {
  return !canConfirmActivation(activationMode(service, host), redeployEnabled);
}
