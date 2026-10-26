import type { ServiceRef } from '../types.js';

export function serviceKey(service: ServiceRef): string {
  return `${service.host}:${service.projectId}/${service.environmentId}/${service.serviceId}`;
}
