export interface DashboardSession { csrf: string; readOnly: boolean; passkeys: number }

let session: DashboardSession | undefined;
const requestError = 'The request could not be completed. Try again.';
export const passkeyRegistrationNotice = 'Register a passkey with keysentry passkey register in your terminal, then reload this page.';

export function configureSession(value: DashboardSession): void {
  session = { ...value };
}

/** Canonical JSON is shared as a wire format; the browser never imports server code. */
export function canonicalBody(value: unknown): string {
  const encode = (item: unknown): string => {
    if (item === null) return 'null';
    if (typeof item === 'string' || typeof item === 'boolean') return JSON.stringify(item);
    if (typeof item === 'number' && Number.isFinite(item)) return JSON.stringify(item);
    if (Array.isArray(item)) return `[${Array.from(item, child => child === undefined ? 'null' : encode(child)).join(',')}]`;
    if (typeof item === 'object') {
      const record = item as Record<string, unknown>;
      return `{${Object.keys(record).sort().filter(key => record[key] !== undefined).map(key => `${JSON.stringify(key)}:${encode(record[key])}`).join(',')}}`;
    }
    throw new Error();
  };
  try { return encode(value); }
  catch { throw new Error('The request contains an unsupported value.'); }
}

function routeName(route: string): string {
  const name = route.startsWith('/api/') ? route.slice(5) : route;
  if (!/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(name)) throw new Error('Choose a valid dashboard action.');
  return name;
}

async function request<T>(route: string, method: 'GET' | 'POST', body?: string, assertion?: string): Promise<T> {
  const name = routeName(route);
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (method === 'POST') {
    if (!session) throw new Error('Open keysentry again from your terminal.');
    headers['Content-Type'] = 'application/json';
    headers['X-CSRF-Token'] = session.csrf;
  }
  if (assertion) headers['X-Passkey-Assertion'] = assertion;
  try {
    const response = await fetch(`/api/${name}`, { method, credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers, ...(body === undefined ? {} : { body }) });
    if (!response.ok) throw new Error();
    return await response.json() as T;
  } catch { throw new Error(requestError); }
}

export async function get<T = unknown>(route: string): Promise<T> { return request<T>(route, 'GET'); }
export async function post<T = unknown>(route: string, body: unknown = {}): Promise<T> { return request<T>(route, 'POST', canonicalBody(body)); }

export async function fetchSession(): Promise<DashboardSession> {
  const value = await get<DashboardSession>('session');
  if (typeof value?.csrf !== 'string' || typeof value?.readOnly !== 'boolean' || !Number.isInteger(value?.passkeys) || value.passkeys < 0) throw new Error(requestError);
  configureSession(value);
  return { ...value };
}

function base64url(bytes: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function decode(value: unknown): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > 100_000) throw new Error(requestError);
  try {
    const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'));
    const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
    if (base64url(bytes.buffer) !== value) throw new Error();
    return bytes;
  } catch { throw new Error(requestError); }
}

type WireOptions = Record<string, unknown> & { publicKey?: Record<string, unknown> };

function publicOptions(options: WireOptions): Record<string, unknown> { return options.publicKey ?? options; }

function descriptors(value: unknown): PublicKeyCredentialDescriptor[] {
  if (!Array.isArray(value)) return [];
  return value.map(item => ({ type: 'public-key', id: decode((item as Record<string, unknown>).id) }));
}

function writable(): void {
  if (!session) throw new Error('Open keysentry again from your terminal.');
  if (session.passkeys === 0) throw new Error(passkeyRegistrationNotice);
  if (session.readOnly) throw new Error('Changes are unavailable in this session.');
}

function credentialWire(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response;
  const common = { id: credential.id, rawId: base64url(credential.rawId), type: credential.type };
  const assertion = response as AuthenticatorAssertionResponse;
  return { ...common, response: { clientDataJSON: base64url(response.clientDataJSON), authenticatorData: base64url(assertion.authenticatorData), signature: base64url(assertion.signature), userHandle: assertion.userHandle ? base64url(assertion.userHandle) : null } };
}

export async function postWithPasskey<T = unknown>(route: string, body: unknown = {}): Promise<T> {
  writable();
  const name = routeName(route);
  const canonical = canonicalBody(body);
  const digestBytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  const bodyDigest = Array.from(new Uint8Array(digestBytes), byte => byte.toString(16).padStart(2, '0')).join('');
  const options = publicOptions(await post<WireOptions>('passkey/challenge', { route: name, bodyDigest }));
  // The server names the RP ID: localhost in local mode, the public host in team mode. The browser still checks that
  // it matches this page's origin.
  const rpId = typeof options.rpId === 'string' && /^[A-Za-z0-9.-]{1,253}$/.test(options.rpId) ? options.rpId : 'localhost';
  let credential: Credential | null;
  try {
    const publicKey: PublicKeyCredentialRequestOptions = {
      challenge: decode(options.challenge), rpId, userVerification: 'required', timeout: 120_000,
      allowCredentials: descriptors(options.allowCredentials),
    };
    credential = await navigator.credentials.get({ publicKey });
  } catch { throw new Error('Passkey verification was not completed. Try again.'); }
  if (!credential) throw new Error('Passkey verification was not completed.');
  let assertion: string;
  try { assertion = base64url(new TextEncoder().encode(JSON.stringify(credentialWire(credential as PublicKeyCredential))).buffer); }
  catch { throw new Error('Passkey verification was not completed. Try again.'); }
  return request<T>(name, 'POST', canonical, assertion);
}

