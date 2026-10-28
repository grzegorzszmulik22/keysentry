import { describe, expect, it } from 'vitest';
import { AuditExportError, buildOtlpLogsBody, createOtlpSink, otlpLogsUrl } from '../../src/audit-export/index.js';
import { createFakeVault } from '../helpers/fake-vault.js';
import { FakeHttp, json, text } from '../helpers/fake-http.js';
import { sampleRecord, unexpected } from './helpers.js';

const target = { kind: 'otlp' as const, id: 'otel', url: 'https://otel.example.com/v1/logs' };
const now = () => new Date('2026-10-28T12:00:00.000Z');
const TOKEN = 'otlp-token-Zq81mNc7Vb2';

describe('OTLP/HTTP JSON logs', () => {
  it('uses the default logs path only when the URL has none', () => {
    expect(otlpLogsUrl('https://otel.example.com')).toBe('https://otel.example.com/v1/logs');
    expect(otlpLogsUrl('https://otel.example.com/')).toBe('https://otel.example.com/v1/logs');
    expect(otlpLogsUrl('https://otel.example.com/custom/logs')).toBe('https://otel.example.com/custom/logs');
  });

  it('builds an ExportLogsServiceRequest with resourceLogs, scopeLogs and logRecords', () => {
    const body = JSON.parse(buildOtlpLogsBody([
      { seq: 1, at: '2026-10-28T10:00:00.123Z', kind: 'vault-set', summary: 'Credential stored.', data: { name: 'OPENAI_API_KEY', ok: true, n: 2, ratio: 0.5, list: ['a'], none: null } },
      { seq: 2, at: '2026-10-28T10:00:01.000Z', kind: 'approval', summary: 'Approved.', actor: 'ana' },
    ], { observedAt: now(), sourceId: 'abc123' }));
    expect(body).toEqual({ resourceLogs: [{
      resource: { attributes: [
        { key: 'service.name', value: { stringValue: 'keysentry' } },
        { key: 'keysentry.source', value: { stringValue: 'abc123' } },
      ] },
      scopeLogs: [{ scope: { name: 'keysentry.audit', version: '1' }, logRecords: [
        { timeUnixNano: '1793181600123000000', observedTimeUnixNano: '1793188800000000000', severityNumber: 9, severityText: 'INFO',
          body: { stringValue: 'Credential stored.' }, attributes: [
            { key: 'keysentry.audit.seq', value: { intValue: '1' } },
            { key: 'keysentry.audit.kind', value: { stringValue: 'vault-set' } },
            { key: 'keysentry.audit.data', value: { kvlistValue: { values: [
              { key: 'name', value: { stringValue: 'OPENAI_API_KEY' } },
              { key: 'ok', value: { boolValue: true } },
              { key: 'n', value: { intValue: '2' } },
              { key: 'ratio', value: { doubleValue: 0.5 } },
              { key: 'list', value: { arrayValue: { values: [{ stringValue: 'a' }] } } },
              { key: 'none', value: {} },
            ] } } },
          ] },
        { timeUnixNano: '1793181601000000000', observedTimeUnixNano: '1793188800000000000', severityNumber: 9, severityText: 'INFO',
          body: { stringValue: 'Approved.' }, attributes: [
            { key: 'keysentry.audit.seq', value: { intValue: '2' } },
            { key: 'keysentry.audit.kind', value: { stringValue: 'approval' } },
            { key: 'keysentry.audit.actor', value: { stringValue: 'ana' } },
          ] },
      ] }],
    }] });
  });

  it('names the log instance as a resource attribute when known', () => {
    const body = JSON.parse(buildOtlpLogsBody([sampleRecord(1)], { observedAt: now(), sourceId: 's', logId: '0123456789abcdef' }));
    expect(body.resourceLogs[0].resource.attributes).toContainEqual({ key: 'keysentry.audit.log', value: { stringValue: '0123456789abcdef' } });
  });

  it('POSTs JSON with the bearer token and custom header from the vault', async () => {
    const http = new FakeHttp().on('POST', /otel\.example\.com\/v1\/logs$/, () => json(200, {}));
    const vault = createFakeVault({ 'audit-export/otel/bearer': Buffer.from(TOKEN), 'audit-export/otel/header': Buffer.from('X-Api-Key: header-value-1') });
    const sink = createOtlpSink(target, { http, vault, now, sourceId: 'abc123' });
    expect(await sink.deliver([sampleRecord(1)])).toEqual({});
    expect(http.calls[0]!.headers).toEqual({ 'content-type': 'application/json', authorization: `Bearer ${TOKEN}`, 'x-api-key': 'header-value-1' });
    expect(JSON.parse(http.calls[0]!.body!).resourceLogs[0].scopeLogs[0].logRecords).toHaveLength(1);
    expect(sink.destination).toBe('OpenTelemetry logs at otel.example.com');
  });

  it('sends without credentials when none are stored', async () => {
    const http = new FakeHttp().on('POST', /otel/, () => text(200, ''));
    await createOtlpSink(target, { http, vault: createFakeVault(), now }).deliver([sampleRecord(1)]);
    expect(http.calls[0]!.headers).toEqual({ 'content-type': 'application/json' });
  });

  it('refuses a custom header the redirect guard would not strip, and malformed credentials, without echoing them', async () => {
    for (const header of ['X-Honeycomb-Team: header-secret-value', 'Host: header-secret-value', 'no colon header-secret-value']) {
      const http = new FakeHttp();
      const vault = createFakeVault({ 'audit-export/otel/header': Buffer.from(header) });
      const error = await createOtlpSink(target, { http, vault, now }).deliver([sampleRecord(1)]).then(unexpected, (caught: unknown) => caught as AuditExportError);
      expect(error).toBeInstanceOf(AuditExportError);
      expect(error.retryable).toBe(false);
      expect(error.message).not.toContain('header-secret-value');
      expect(http.calls).toHaveLength(0);
    }
    const vault = createFakeVault({ 'audit-export/otel/bearer': Buffer.from('two words') });
    await expect(createOtlpSink(target, { http: new FakeHttp(), vault, now }).deliver([sampleRecord(1)])).rejects.toThrow('unsupported format');
  });

  it('reports a partial success without retrying it', async () => {
    const http = new FakeHttp().on('POST', /otel/, () => json(200, { partialSuccess: { rejectedLogRecords: '2', errorMessage: 'upstream detail' } }));
    const outcome = await createOtlpSink(target, { http, vault: createFakeVault(), now }).deliver([sampleRecord(1), sampleRecord(2), sampleRecord(3)]);
    expect(outcome.warnings).toEqual(['The OpenTelemetry receiver accepted the batch but rejected 2 of 3 records; OTLP forbids resending them.']);
    expect(JSON.stringify(outcome)).not.toContain('upstream detail');
  });

  it('retries only 429, 502, 503 and 504, honours Retry-After, and never echoes the response body', async () => {
    for (const [status, retryable] of [[429, true], [502, true], [503, true], [504, true], [400, false], [401, false], [500, false], [404, false]] as const) {
      const http = new FakeHttp().on('POST', /otel/, () => text(status, `body with ${TOKEN}`, { 'retry-after': '7' }));
      const vault = createFakeVault({ 'audit-export/otel/bearer': Buffer.from(TOKEN) });
      const error = await createOtlpSink(target, { http, vault, now }).deliver([sampleRecord(1)]).then(unexpected, (caught: unknown) => caught as AuditExportError);
      expect(error.message).toBe(`The OpenTelemetry receiver answered HTTP ${status}.`);
      expect(error.retryable).toBe(retryable);
      expect(error.retryAfterMs).toBe(retryable ? 7000 : undefined);
    }
  });

  it('turns a transport failure into fixed text', async () => {
    const http = { request: async () => { throw new Error(`socket hang up near ${TOKEN}`); } };
    const vault = createFakeVault({ 'audit-export/otel/bearer': Buffer.from(TOKEN) });
    const error = await createOtlpSink(target, { http, vault, now }).deliver([sampleRecord(1)]).then(unexpected, (caught: unknown) => caught as AuditExportError);
    expect(error.message).toBe('Could not reach the OpenTelemetry receiver.');
    expect(error.retryable).toBe(true);
  });
});
