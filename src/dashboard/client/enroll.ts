// The team dashboard's passkey enrollment page (/enroll). The invitation token arrives in the URL fragment, so the
// browser never sends it with the page request; this script removes it from the address bar and posts it.
// The passkey created here is only a candidate until team admins sign it into the roster.

const failure = 'The passkey could not be added. Ask a team admin for a new enrollment link.';

function base64url(bytes: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function decode(value: unknown): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,2048}$/.test(value)) throw new Error(failure);
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

async function send(path: string, body: unknown): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(path, { method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body) });
  } catch { throw new Error(failure); }
  let result: unknown = null;
  try { result = await response.json(); } catch { /* fixed text below */ }
  const record = result && typeof result === 'object' && !Array.isArray(result) ? result as Record<string, unknown> : {};
  if (!response.ok) throw new Error(typeof record.error === 'string' && record.error.length <= 300 ? record.error : failure);
  return record;
}

interface CreationOptions {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout: number;
  attestation: AttestationConveyancePreference;
  authenticatorSelection: AuthenticatorSelectionCriteria;
  excludeCredentials: { type: 'public-key'; id: string }[];
}

export async function startEnrollment(doc: Document = document): Promise<void> {
  const status = doc.getElementById('enroll-status');
  const button = doc.getElementById('enroll-start') as HTMLButtonElement | null;
  if (!status || !button) return;
  const token = location.hash.replace(/^#/, '');
  // Keep the token out of the address bar, history and any later navigation.
  history.replaceState(null, '', '/enroll');
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) { status.textContent = 'This enrollment link is not complete. Open the full link a team admin sent you.'; return; }
  const begin = async (): Promise<{ options: CreationOptions; memberName: string }> => {
    const result = await send('/enroll/options', { token });
    const member = result.member as { name?: unknown } | undefined;
    return { options: result.publicKey as CreationOptions, memberName: typeof member?.name === 'string' ? member.name : '' };
  };
  let ready: { options: CreationOptions; memberName: string } | null;
  try { ready = await begin(); } catch (error) { status.textContent = (error as Error).message; return; }
  const memberName = ready.memberName;
  status.textContent = memberName ? `This link adds a passkey for ${memberName}. Choose your device or security key in the next prompt.` : 'Choose your device or security key in the next prompt.';
  button.disabled = false;
  let done = false;
  button.addEventListener('click', async () => {
    if (done || button.disabled) return;
    button.disabled = true;
    status.textContent = 'Follow your browser’s passkey prompt.';
    try {
      // Each attempt uses a fresh challenge; a cancelled prompt can be retried without reloading the page.
      const options = (ready ??= await begin()).options;
      ready = null;
      const publicKey: PublicKeyCredentialCreationOptions = {
        rp: { id: options.rp.id, name: options.rp.name },
        user: { id: decode(options.user.id), name: options.user.name, displayName: options.user.displayName },
        challenge: decode(options.challenge), pubKeyCredParams: options.pubKeyCredParams, timeout: options.timeout,
        attestation: options.attestation, authenticatorSelection: options.authenticatorSelection,
        excludeCredentials: options.excludeCredentials.map(item => ({ type: 'public-key' as const, id: decode(item.id) })),
      };
      const credential = await navigator.credentials.create({ publicKey }) as PublicKeyCredential | null;
      if (!credential) throw new Error('The passkey prompt was closed. Choose Create passkey to try again.');
      const response = credential.response as AuthenticatorAttestationResponse;
      const result = await send('/enroll/finish', { token, clientDataJSON: base64url(response.clientDataJSON), attestationObject: base64url(response.attestationObject) });
      const id = typeof result.credentialId === 'string' ? result.credentialId : '';
      status.textContent = `Passkey created. It works after a team admin adds it to the roster. Give them this credential id: ${id}`;
      done = true;
    } catch (error) {
      status.textContent = error instanceof Error && error.message ? error.message : failure;
    } finally { button.disabled = done; }
  });
}

if (typeof document !== 'undefined' && document.getElementById('enroll-status')) void startEnrollment();
