import type { HttpClient, HttpRequest } from '../types.js';

/** Never propagate transport diagnostics or upstream payloads: either can contain secrets. */
export async function requestJson<T>(http: HttpClient, host: string, req: HttpRequest): Promise<T> {
  let response;
  try {
    response = await http.request(req);
  } catch {
    throw new Error(`${host} request failed`);
  }
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`${host} request failed (HTTP ${response.status})`);
  }
  if (!response.text.trim()) return undefined as T;
  try {
    return response.json<T>();
  } catch {
    throw new Error(`${host} returned invalid JSON`);
  }
}
