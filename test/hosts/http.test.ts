import { describe, expect, it } from 'vitest';
import { FakeHttp, json, text } from '../helpers/fake-http.js';
import { requestJson } from '../../src/hosts/http.js';

describe('safe host HTTP boundary', () => {
  const req = { method: 'POST' as const, url: 'https://host.test/api', headers: { Authorization: 'Bearer admin-token' }, body: '{"value":"private-value"}' };

  it('forwards requests and accepts empty successful write responses', async () => {
    const http = new FakeHttp().on('POST', /^https:\/\/host\.test\/api$/, () => text(204, ''));
    expect(await requestJson(http, 'Test', req)).toBeUndefined();
    expect(http.calls).toEqual([req]);
  });

  it('does not expose response bodies, request bodies or thrown transport details', async () => {
    for (const handler of [
      () => json(400, { error: 'admin-token private-value' }),
      () => { throw new Error('admin-token private-value'); },
      () => text(200, 'private-value invalid json'),
    ]) {
      const http = new FakeHttp().on('POST', /^https:\/\/host\.test\/api$/, handler);
      const error = await requestJson(http, 'Test', req).catch((err: unknown) => err);
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).not.toMatch(/admin-token|private-value/);
      expect(http.calls).toEqual([req]);
    }
  });
});
