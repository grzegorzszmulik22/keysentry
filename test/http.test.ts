import { afterEach, describe, expect, test, vi } from 'vitest';
import { createFetchHttp, ResponseTooLargeError } from '../src/http.js';

afterEach(() => vi.unstubAllGlobals());

function respond(response: Response) {
  const fetchImpl = vi.fn(async () => response);
  vi.stubGlobal('fetch', fetchImpl);
  return fetchImpl;
}

describe('createFetchHttp', () => {
  test('forwards the request and preserves response status, JSON and normalized headers', async () => {
    const fetchImpl = respond(new Response('{"ok":true}', { status: 201, headers: { 'X-Request-Id': 'id-1' } }));
    const request = { method: 'POST' as const, url: 'https://api.openai.com/v1/keys', headers: { authorization: 'Bearer value' }, body: '{}' };
    const response = await createFetchHttp({ timeoutMs: 1200 }).request(request);
    expect(fetchImpl).toHaveBeenCalledWith(request.url, expect.objectContaining({
      method: 'POST', headers: request.headers, body: '{}', signal: expect.any(AbortSignal),
    }));
    expect(response.status).toBe(201);
    expect(response.headers['x-request-id']).toBe('id-1');
    expect(response.text).toBe('{"ok":true}');
    expect(response.json()).toEqual({ ok: true });
  });

  test('returns a redirect response with fetch configured to leave redirects manual', async () => {
    const fetchImpl = respond(new Response(null, { status: 302, headers: { location: 'https://other.example/path' } }));
    const response = await createFetchHttp().request({ method: 'GET', url: 'https://api.openai.com/start' });
    expect(fetchImpl).toHaveBeenCalledWith('https://api.openai.com/start', expect.objectContaining({ redirect: 'manual' }));
    expect(response.status).toBe(302);
    expect(response.headers.location).toBe('https://other.example/path');
    expect(response.text).toBe('');
  });

  test('decodes UTF-8 split across chunks with Response.text BOM behavior', async () => {
    respond(new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([0xef, 0xbb, 0xbf, 0xe2]));
        controller.enqueue(new Uint8Array([0x82, 0xac]));
        controller.close();
      },
    })));
    const response = await createFetchHttp({ maxBytes: 6 }).request({ method: 'GET', url: 'https://api.openai.com/' });
    expect(response.text).toBe('€');
  });

  test('accepts a response exactly at the configured byte limit', async () => {
    respond(new Response('abcd'));
    const response = await createFetchHttp({ maxBytes: 4 }).request({ method: 'GET', url: 'https://api.openai.com/' });
    expect(response.text).toBe('abcd');
  });

  test('cancels a streamed response once cumulative bytes exceed the limit', async () => {
    let cancelled = false;
    respond(new Response(new ReadableStream({
      start(controller) {
        for (let i = 0; i < 3; i += 1) controller.enqueue(new TextEncoder().encode('abc'));
        controller.close();
      },
      cancel() { cancelled = true; },
    })));
    await expect(createFetchHttp({ maxBytes: 4 }).request({ method: 'GET', url: 'https://api.openai.com/private/path?key=hidden' }))
      .rejects.toBeInstanceOf(ResponseTooLargeError);
    expect(cancelled).toBe(true);
  });

  test('counts bytes rather than decoded characters', async () => {
    respond(new Response('€€'));
    await expect(createFetchHttp({ maxBytes: 5 }).request({ method: 'GET', url: 'https://api.openai.com/' }))
      .rejects.toMatchObject({ code: 'RESPONSE_TOO_LARGE' });
  });

  test('size error contains only the host and limit from the request', async () => {
    respond(new Response('12345'));
    const error = await createFetchHttp({ maxBytes: 4 })
      .request({ method: 'GET', url: 'https://username:password@API.OPENAI.COM:8443/private/path?token=hidden' })
      .catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(ResponseTooLargeError);
    expect(error).toMatchObject({ name: 'ResponseTooLargeError', code: 'RESPONSE_TOO_LARGE' });
    const message = (error as Error).message;
    expect(message).toContain('api.openai.com');
    expect(message).toContain('4');
    for (const forbidden of ['username', 'password', '8443', 'private', 'path', 'token', 'hidden']) {
      expect(message).not.toContain(forbidden);
    }
  });

  test('redacts a secret-shaped value in the hostname of a size error', async () => {
    const secret = `sk-or-v1-${'a'.repeat(64)}`;
    respond(new Response('12'));
    const error = await createFetchHttp({ maxBytes: 1 })
      .request({ method: 'GET', url: `https://${secret}.example.com/private?token=hidden` })
      .catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(ResponseTooLargeError);
    expect((error as Error).message).toBe('Response from «redacted».example.com exceeds the 1 byte limit.');
    expect((error as Error).message).not.toContain(secret);
  });

  test('applies a 16 MiB limit by default', async () => {
    respond(new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(16 * 1024 * 1024));
        controller.enqueue(new Uint8Array([1]));
        controller.close();
      },
    })));
    await expect(createFetchHttp().request({ method: 'GET', url: 'https://api.openai.com/' }))
      .rejects.toMatchObject({ code: 'RESPONSE_TOO_LARGE', message: expect.stringContaining('16777216') });
  });

  test('preserves the size error if cancelling the stream throws', async () => {
    respond(new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2]));
        controller.enqueue(new Uint8Array([3]));
        controller.close();
      },
      cancel() { throw new Error('cancel failed'); },
    })));
    await expect(createFetchHttp({ maxBytes: 1 }).request({ method: 'GET', url: 'https://api.openai.com/' }))
      .rejects.toMatchObject({ code: 'RESPONSE_TOO_LARGE' });
  });

  test('rethrows a body stream failure', async () => {
    const failure = new Error('body failed');
    respond(new Response(new ReadableStream({ start(controller) { controller.error(failure); } })));
    await expect(createFetchHttp().request({ method: 'GET', url: 'https://api.openai.com/' })).rejects.toBe(failure);
  });
});
