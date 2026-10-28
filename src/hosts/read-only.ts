import type { HostAdapter, ServiceRef } from '../types.js';

/**
 * An optional host extension beside the fixed HostAdapter contract: services that keysentry reads but never writes,
 * such as a Kubernetes Secret that a controller (External Secrets, Sealed Secrets, the Vault Secrets Operator,
 * cert-manager) restores from its own source. Their values are read for fingerprints, so a rotation sees every copy
 * of a key; a key also held there is never revoked automatically, because that copy keeps the old value until the
 * controller's source changes.
 */
export interface ReadOnlyServices {
  /** Fixed text completing "keysentry does not write it: it is …", or null when keysentry may write the service. */
  readOnlyReason(service: ServiceRef): Promise<string | null>;
}

export function hasReadOnlyServices(host: object): host is ReadOnlyServices {
  return 'readOnlyReason' in host && typeof (host as { readOnlyReason?: unknown }).readOnlyReason === 'function';
}

/** For adapters that wrap a host: forward the extension when the wrapped host has it, so it is never lost. */
export function readOnlyServicesOf(host: HostAdapter): Partial<ReadOnlyServices> {
  return hasReadOnlyServices(host) ? { readOnlyReason: service => host.readOnlyReason(service) } : {};
}
