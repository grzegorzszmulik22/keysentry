import { existsSync } from 'node:fs';
import type { HostId, Incident } from '../types.js';

export interface DetectedPlatform {
  platform: 'railway' | 'fly' | 'render' | 'github-actions' | 'docker' | 'unknown';
  host: HostId | null;
}

export function detectPlatform(
  env: Readonly<Record<string, string | undefined>>, options: { docker?: boolean } = {},
): DetectedPlatform {
  if (env.RAILWAY_ENVIRONMENT) return { platform: 'railway', host: 'railway' };
  if (env.FLY_APP_NAME) return { platform: 'fly', host: 'fly' };
  if (env.RENDER && env.RENDER !== 'false') return { platform: 'render', host: 'render' };
  if (env.GITHUB_ACTIONS === 'true') return { platform: 'github-actions', host: 'github-actions' };
  if (options.docker ?? existsSync('/.dockerenv')) return { platform: 'docker', host: null };
  return { platform: 'unknown', host: null };
}

export function ownPlatformIncident(incident: Incident, platform: DetectedPlatform): boolean {
  return platform.host !== null && incident.host === platform.host;
}
