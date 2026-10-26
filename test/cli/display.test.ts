import { describe, expect, it } from 'vitest';
import { serviceKey } from '../../src/core/index.js';
import { humanizeServices, serviceLabel } from '../../src/cli/display.js';
import type { ServiceRef } from '../../src/types.js';

function service(overrides: Partial<ServiceRef> = {}): ServiceRef {
  return { host: 'railway', projectId: 'project-id', projectName: 'backend', serviceId: 'service-id', serviceName: 'api', environmentId: 'environment-id', environmentName: 'production', ...overrides };
}

describe('human service labels', () => {
  it('uses project and service names with the environment', () => {
    expect(serviceLabel(service())).toBe('railway:backend/api@production');
    expect(serviceLabel(service({ environmentName: '', environmentId: 'preview' }))).toBe('railway:backend/api@preview');
    expect(serviceLabel(service({ environmentName: '', environmentId: '' }))).toBe('railway:backend/api');
  });

  it('shows dotenv file paths relative to a POSIX scan root', () => {
    const dotenv = service({ host: 'dotenv', projectId: '/work/payments', projectName: 'payments', serviceId: '/work/payments/services/api/.env', serviceName: '/work/payments/services/api/.env', environmentId: '', environmentName: '' });
    expect(serviceLabel(dotenv)).toBe('dotenv:payments/services/api/.env');
  });

  it('shows dotenv file paths relative to a Windows scan root on any platform', () => {
    const dotenv = service({ host: 'dotenv', projectId: 'C:\\work\\payments', projectName: 'C:\\work\\payments', serviceId: 'C:\\work\\payments\\services\\api\\.env', serviceName: 'C:\\work\\payments\\services\\api\\.env', environmentId: '', environmentName: '' });
    expect(serviceLabel(dotenv)).toBe('dotenv:payments/services/api/.env');
  });

  it('falls back to safe basenames when names or dotenv locations are outside the scan root', () => {
    expect(serviceLabel(service({ projectName: '/private/work/backend', serviceName: 'D:\\private\\api' }))).toBe('railway:backend/api@production');
    const dotenv = service({ host: 'dotenv', projectId: 'C:\\work\\payments', projectName: '', serviceId: 'D:\\private\\.env', serviceName: '', environmentId: '', environmentName: '' });
    expect(serviceLabel(dotenv)).toBe('dotenv:payments/.env');
  });

  it('replaces keys inside sealed clusters and handles overlapping file names once', () => {
    const dotenv = service({ host: 'dotenv', projectId: '/work/payments', projectName: 'payments', serviceId: '/work/payments/.env', serviceName: '.env', environmentId: '', environmentName: '' });
    const production = { ...dotenv, serviceId: '/work/payments/.env.production', serviceName: '.env.production' };
    const text = `${serviceKey(production)}: TOKEN\nsealed:${serviceKey(dotenv)}:TOKEN\n${serviceKey(production)}: SECOND`;
    expect(humanizeServices(text, [dotenv, production])).toBe('dotenv:payments/.env.production: TOKEN\nsealed:dotenv:payments/.env:TOKEN\ndotenv:payments/.env.production: SECOND');
  });

  it('uses core project and environment context to disambiguate legacy labels', () => {
    const production = service();
    const preview = service({ environmentId: 'preview-id', environmentName: 'preview' });
    const text = '- `railway/api:TOKEN` (project `backend`, environment `preview`)\n- `railway/api:TOKEN` (project `backend`, environment `production`)';
    expect(humanizeServices(text, [production, preview])).toBe('- `railway:backend/api@preview:TOKEN` (project `backend`, environment `preview`)\n- `railway:backend/api@production:TOKEN` (project `backend`, environment `production`)');
  });

  it('humanizes legacy core labels and path contexts without rewriting the journal path', () => {
    const dotenv = service({ host: 'dotenv', projectId: '/work/payments', projectName: '/work/payments', serviceId: '/work/payments/.env', serviceName: '.env', environmentId: '', environmentName: '' });
    const text = '- `dotenv/.env:TOKEN` (project `/work/payments`, environment `default`)\n- `dotenv/.env` (project `/work/payments`, environment `default`; `' + serviceKey(dotenv) + '`)\nJournal: /work/payments/.keysentry/journal.jsonl';
    expect(humanizeServices(text, [dotenv])).toBe('- `dotenv:payments/.env:TOKEN` (project `payments`, environment `default`)\n- `dotenv:payments/.env` (project `payments`, environment `default`; `dotenv:payments/.env`)\nJournal: /work/payments/.keysentry/journal.jsonl');
  });

  it('does not replace service names that merely have a matching prefix', () => {
    const value = service();
    expect(humanizeServices('railway/apiary and unrelated text', [value])).toBe('railway/apiary and unrelated text');
    expect(humanizeServices('no services', [])).toBe('no services');
  });

  it('humanizes Windows keys in JSON formatted human diagnostics', () => {
    const dotenv = service({ host: 'dotenv', projectId: 'C:\\work\\payments', projectName: 'payments', serviceId: 'C:\\work\\payments\\.env', serviceName: '.env', environmentId: '', environmentName: '' });
    const text = JSON.stringify({ serviceKey: serviceKey(dotenv), journal: 'C:\\work\\payments\\.keysentry\\journal.jsonl' });
    expect(JSON.parse(humanizeServices(text, [dotenv]))).toEqual({ serviceKey: 'dotenv:payments/.env', journal: 'C:\\work\\payments\\.keysentry\\journal.jsonl' });
  });
});
