import { get, type DashboardSession } from '../api.js';
import { button, notice, table } from '../components.js';
import { download } from './components-b.js';

const ROLE_TEXT: Record<'viewer' | 'operator' | 'admin', string> = {
  viewer: 'Viewer: can read this dashboard.',
  operator: 'Operator: can ask for and approve rotations and disarm autopilot, each with your own passkey. A change runs once enough team members approve it.',
  admin: 'Admin: can also ask for and approve settings, notification, vault and reveal changes. Roster and policy changes are signed on admins\' own computers.',
};

interface PendingPasskey { memberId: string; credentialId: string; createdAt: string; fingerprint: string; reportedAuthenticator?: string }
interface Candidates { pending: PendingPasskey[]; card: unknown }

function code(text: string): HTMLElement {
  const element = document.createElement('code'); element.textContent = text; return element;
}

/**
 * Admins: passkeys members created on this dashboard wait here as public candidates. The card holds public keys only;
 * an admin adds one on their own computer with `keysentry team add-passkey <member> --card <file>` (review H3).
 */
function pendingPasskeys(): HTMLElement {
  const section = document.createElement('section'); section.className = 'screen-a-section';
  const heading = document.createElement('h2'); heading.textContent = 'Passkeys waiting for an admin';
  const body = document.createElement('div');
  body.textContent = 'Loading passkeys waiting for an admin.';
  section.append(heading, body);
  void (async () => {
    try {
      const result = await get<Candidates>('team/candidates');
      body.replaceChildren();
      if (!Array.isArray(result.pending) || !result.pending.length || !result.card) { body.textContent = 'No passkeys are waiting.'; return; }
      body.append(table(['Member', 'Created', 'Fingerprint', 'Credential id'], result.pending.map(item => [item.memberId, item.createdAt, code(item.fingerprint), code(item.credentialId)]),
        'Passkeys waiting for an admin'));
      const help = document.createElement('p');
      help.textContent = 'Compare each fingerprint with the member. Then download the card and, on your own computer, run keysentry team add-passkey <member> --card <file>. The card holds public keys only.';
      const card = result.card;
      body.append(help, button('Download passkey card', () => {
        download(new Blob([`${JSON.stringify(card, null, 2)}\n`], { type: 'application/json' }), 'keysentry-passkeys.json');
      }, 'secondary'));
    } catch { body.textContent = 'The waiting passkeys could not be loaded. Run keysentry team passkeys pending on the dashboard host.'; }
  })();
  return section;
}

/** Team mode: who is signed in, and the identity provider's issuer and subject an admin can pin in the roster. */
export function renderAccount(session: DashboardSession): HTMLElement {
  const root = document.createElement('div'); root.className = 'screen-a';
  if (!session.team || !session.member) {
    root.append(notice('info', 'Local dashboard', 'This dashboard runs on your computer for you alone. Team accounts appear when keysentry runs as the team dashboard.'));
    return root;
  }
  const { member, identity } = session;
  const intro = document.createElement('p');
  intro.textContent = `Signed in as ${member.name} (${member.id}). ${ROLE_TEXT[member.role]}`;
  root.append(intro);
  if (identity) {
    root.append(table(['Field', 'Value'], [['Issuer (iss)', code(identity.issuer)], ['Subject (sub)', code(identity.subject)]], 'Your single sign-on identity'));
    const command = `keysentry team sso ${member.id} --issuer ${identity.issuer} --subject ${identity.subject}`;
    root.append(identity.pinned
      ? notice('ok', 'Identity pinned', 'The team roster pins your sign-in to this issuer and subject, so a reassigned email address cannot sign in as you.')
      : notice('info', 'Pin this identity', `Your sign-in is matched by email. An admin can pin it to this issuer and subject with: ${command}`));
  }
  const passkeys = document.createElement('p');
  passkeys.textContent = session.passkeys > 0
    ? `${session.passkeys} of your passkeys ${session.passkeys === 1 ? 'works' : 'work'} on this dashboard.`
    : 'You have no passkey for this dashboard yet. Ask a team admin for an enrollment link (keysentry team invite on their computer), then ask them to add the new passkey to the roster.';
  root.append(passkeys);
  if (member.role === 'admin') root.append(pendingPasskeys());
  return root;
}
