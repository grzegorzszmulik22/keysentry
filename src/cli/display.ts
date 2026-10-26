import { posix, win32 } from 'node:path';
import { serviceKey } from '../core/index.js';
import type { ServiceRef } from '../types.js';

function absolute(value: string): boolean {
  return posix.isAbsolute(value) || win32.isAbsolute(value);
}

function pathFlavor(value: string) {
  return /^[A-Za-z]:[\\/]|^\\\\/.test(value) || value.includes('\\') ? win32 : posix;
}

function name(value: string, fallback: string): string {
  const clean = value.replace(/[\r\n\x00-\x1f\x7f]+/g, ' ').trim();
  const result = absolute(clean) ? pathFlavor(clean).basename(clean) : clean;
  return result && result !== '.' && result !== '..' ? result : fallback;
}

function projectName(service: ServiceRef): string {
  return name(service.projectName || service.projectId, 'project');
}

function dotenvFile(service: ServiceRef): string {
  if (absolute(service.projectId) && absolute(service.serviceId)) {
    const path = pathFlavor(service.projectId);
    const relative = path.relative(service.projectId, service.serviceId);
    if (relative && !absolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`)) {
      return relative.replace(/\\/g, '/');
    }
  }
  const candidate = service.serviceName || service.serviceId;
  if (candidate && !absolute(candidate) && !candidate.split(/[\\/]/).includes('..')) return name(candidate, '.env').replace(/\\/g, '/');
  return name(pathFlavor(candidate).basename(candidate), '.env');
}

/** Human-facing names never expose dotenv's absolute-path internal service identifiers. */
export function serviceLabel(service: ServiceRef): string {
  const serviceName = service.host === 'dotenv' ? dotenvFile(service) : name(service.serviceName || service.serviceId, 'shared');
  const environment = service.environmentName || service.environmentId;
  return `${service.host}:${projectName(service)}/${serviceName}${environment ? `@${name(environment, 'default')}` : ''}`;
}

function codeText(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').replace(/`/g, "'");
}

function escape(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function replaceKnown(text: string, replacements: Map<string, string>): string {
  const entries = [...replacements.keys()].filter(Boolean).sort((a, b) => b.length - a.length);
  if (!entries.length) return text;
  return text.replace(new RegExp(entries.map(escape).join('|'), 'g'), (matched: string, offset: number) => {
    // Do not rewrite prefixes of a different service/file (for example api/apiary or .env/.env.local).
    const next = text[offset + matched.length];
    return next && /[A-Za-z0-9_./\\-]/.test(next) ? matched : replacements.get(matched)!;
  });
}

/** Render internal keys and legacy core report labels using the known service metadata. */
export function humanizeServices(text: string, services: ServiceRef[]): string {
  if (!services.length) return text;
  const raw = new Map<string, string>();
  const legacy = new Map<string, Set<string>>();
  for (const service of services) {
    const label = serviceLabel(service);
    const key = serviceKey(service);
    raw.set(key, label);
    raw.set(JSON.stringify(key).slice(1, -1), label);
    const oldLabel = codeText(`${service.host}/${service.serviceName || service.serviceId || 'shared'}`);
    const project = codeText(service.projectName || service.projectId);
    const environment = codeText(service.environmentName || service.environmentId || 'default');
    // The core renderer supplies this context, so equal service names in different
    // projects/environments remain unambiguous before replacing standalone labels.
    const contextual = new RegExp(`${escape(oldLabel)}((?::[^\x60\r\n]*)?\x60 \\(project \x60${escape(project)}\x60, environment \x60${escape(environment)}\x60)`, 'g');
    text = text.replace(contextual, (_matched, context: string) => `${label}${context}`);
    const labels = legacy.get(oldLabel) ?? new Set<string>();
    labels.add(label);
    legacy.set(oldLabel, labels);
  }
  text = replaceKnown(text, raw);
  text = replaceKnown(text, new Map([...legacy].map(([key, labels]) => [key, [...labels].join(', ')])));
  for (const service of services) {
    const original = service.projectName || service.projectId;
    if (absolute(original)) {
      text = text.split(`project \x60${codeText(original)}\x60`).join(`project \x60${projectName(service)}\x60`);
    }
  }
  return text;
}
