import type { DashboardSession } from '../api.js';
import { notice, table } from '../components.js';

const ROLE_TEXT: Record<'viewer' | 'operator' | 'admin', string> = {
  viewer: 'Viewer: can read this dashboard.',
  operator: 'Operator: can approve rotations and disarm autopilot, each change with your own passkey.',
  admin: 'Admin: can also change settings, notifications, the roster and the policy.',
};

function code(text: string): HTMLElement {
  const element = document.createElement('code'); element.textContent = text; return element;
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
    : 'You have no passkey for this dashboard yet. Ask a team admin for an enrollment link (keysentry team invite), then ask them to add the new passkey to the roster.';
  root.append(passkeys);
  return root;
}
