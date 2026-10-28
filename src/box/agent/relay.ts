import type { HandshakeMessage } from '../handshake/index.js';
import type { HttpClient } from '../../types.js';

/**
 * The untrusted path between the box and the CLI. It sees public keys, attestation tokens, signatures and ciphertext
 * only. Both endpoints verify everything they read from it; a relay can delay or drop messages but not authorize them.
 */
export interface BoxRelay {
  publish(message: HandshakeMessage): Promise<void>;
  /** Queued messages for this box, optionally one session's. Untrusted input. */
  poll(sessionId?: string): Promise<unknown[]>;
}

export class BoxRelayError extends Error {
  constructor(message = 'The relay could not be reached. Try again in a minute.') { super(message); this.name = 'BoxRelayError'; }
}

const MAX_POLL_MESSAGES = 256;

/** Control-plane HTTP routes `/boxes/:boxId/messages` with a bearer credential that never goes in the URL. */
export function createHttpBoxRelay(options: { http: HttpClient; origin: string; boxId: string; credential: () => Promise<string> }): BoxRelay {
  const origin = new URL(options.origin);
  if (origin.origin !== options.origin || origin.username || origin.password) throw new BoxRelayError('The relay address is invalid.');
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(options.boxId)) throw new BoxRelayError('The box id is invalid.');
  const url = (sessionId?: string) => `${origin.origin}/boxes/${options.boxId}/messages${sessionId === undefined ? '' : `?sessionId=${sessionId}`}`;
  async function headers(): Promise<Record<string, string>> {
    return { authorization: `Bearer ${await options.credential()}`, accept: 'application/json' };
  }
  return {
    async publish(message) {
      let status: number;
      try {
        status = (await options.http.request({ method: 'POST', url: url(),
          headers: { ...await headers(), 'content-type': 'application/json' }, body: JSON.stringify(message) })).status;
      } catch { throw new BoxRelayError(); }
      if (status !== 201) throw new BoxRelayError(status === 401 || status === 403 ? 'The relay refused this box\'s credential.' : undefined);
    },
    async poll(sessionId) {
      if (sessionId !== undefined && !/^[A-Za-z0-9_-]{1,128}$/.test(sessionId)) throw new BoxRelayError('The session id is invalid.');
      let body: unknown;
      try {
        const response = await options.http.request({ method: 'GET', url: url(sessionId), headers: await headers() });
        if (response.status !== 200) throw new BoxRelayError(response.status === 401 || response.status === 403 ? 'The relay refused this box\'s credential.' : undefined);
        body = response.json();
      } catch (error) { throw error instanceof BoxRelayError ? error : new BoxRelayError(); }
      const messages = (body as { messages?: unknown } | null)?.messages;
      if (!Array.isArray(messages) || messages.length > MAX_POLL_MESSAGES) throw new BoxRelayError('The relay sent a reply this version does not understand.');
      return messages;
    },
  };
}
