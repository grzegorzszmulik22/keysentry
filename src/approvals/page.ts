export interface ApprovalPageDetails {
  digest: string;
  kind: string;
  keyCount: number;
  expiresAt: string;
  status: string;
  /** Team mode: distinct team approvals so far and how many are needed. */
  quorum?: { approvals: number; required: number };
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);
}

function document(title: string, content: string, script = false): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>${script ? '<script src="/static/approve.js" defer></script>' : ''}</head><body><main>${content}</main></body></html>`;
}

export function approvedOutcome(watcherCheckMinutes: number): string {
  return `Approved. The watcher will carry this out on its next check (within about ${watcherCheckMinutes} minutes).`;
}

export function approvalPage(details: ApprovalPageDetails, watcherCheckMinutes = 10): string {
  const outcome = details.status === 'pending' ? '' : details.status === 'approved' ? approvedOutcome(watcherCheckMinutes)
    : details.status === 'executed' ? 'Executed. The watcher has carried out this action.'
    : details.status === 'superseded' ? 'This request was replaced by a newer version.' : 'This request is no longer pending.';
  return document('Approve an action | keysentry', `<h1>Approve an action</h1><dl><dt>Action</dt><dd>${escapeHtml(details.kind)}</dd><dt>Keys</dt><dd>${details.keyCount} ${details.keyCount === 1 ? 'key' : 'keys'}</dd><dt>Expires</dt><dd><time>${escapeHtml(details.expiresAt)}</time></dd>${details.quorum ? `<dt>Team approvals</dt><dd>${details.quorum.approvals} of ${details.quorum.required}</dd>` : ''}</dl><button id="approve" type="button" data-digest="${escapeHtml(details.digest)}"${details.status === 'pending' ? '' : ' disabled'}>Approve with a passkey</button><p id="result" role="status" aria-live="polite">${escapeHtml(outcome)}</p><p><a href="/disarm">Turn off autopilot</a></p>`, true);
}

export function disarmPage(): string {
  return document('Turn off autopilot | keysentry', '<h1>Turn off autopilot</h1><p>Type DISARM to turn off automatic rotations. You can re-arm autopilot on your computer.</p><form action="/disarm" method="post"><label for="confirm">Confirmation</label><input id="confirm" name="confirm" required autocomplete="off" spellcheck="false"><button type="submit">Turn off autopilot</button></form>');
}

export function disarmedPage(): string {
  return document('Autopilot is off | keysentry', '<h1>Autopilot is off</h1><p>Autopilot is off. Nothing will rotate automatically until you re-arm it on your computer.</p>');
}

/** Static script: no action data or application values are interpolated into JavaScript. */
export const APPROVE_JS = `'use strict';
(() => {
  const button = document.getElementById('approve');
  const result = document.getElementById('result');
  if (!button || !result) return;
  function bytes(value) {
    const text = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(text, (char) => char.charCodeAt(0));
  }
  function base64url(value) {
    let text = '';
    for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
    return btoa(text).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }
  async function post(path, data) {
    const response = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
    const body = await response.json();
    if (!response.ok) {
      result.textContent = typeof body.text === 'string' ? body.text : 'Approval could not be completed. Please try again.';
      return null;
    }
    return body;
  }
  button.addEventListener('click', async () => {
    button.disabled = true;
    result.textContent = 'Waiting for your passkey.';
    try {
      const actionPath = location.pathname;
      if (!/^\\/a\\/[A-Za-z0-9_-]{1,128}$/.test(actionPath)) throw new Error();
      const digest = button.dataset.digest;
      if (typeof digest !== 'string' || !/^[a-f0-9]{64}$/.test(digest)) throw new Error();
      const options = await post(actionPath + '/challenge', { digest });
      if (!options) return;
      const credential = await navigator.credentials.get({ publicKey: {
        challenge: bytes(options.challenge), rpId: options.rpId,
        allowCredentials: options.allowCredentials.map((item) => ({ type: 'public-key', id: bytes(item.id) })),
        userVerification: 'required', timeout: 60000
      } });
      if (!credential) throw new Error();
      const approved = await post(actionPath + '/assert', {
        digest,
        credentialId: base64url(credential.rawId),
        clientDataJSON: base64url(credential.response.clientDataJSON),
        authenticatorData: base64url(credential.response.authenticatorData),
        signature: base64url(credential.response.signature)
      });
      if (approved) result.textContent = approved.text;
    } catch {
      result.textContent = 'Approval could not be completed. Please try again.';
    } finally {
      button.disabled = false;
    }
  });
})();
`;
