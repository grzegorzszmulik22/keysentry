import { get, postWithPasskey } from '../api.js';
import type { DashboardSession } from '../api.js';
import { button, emptyState } from '../components.js';
import { documentationLink, element, section } from './components-a.js';
import type { PlatformView } from './components-a.js';
import { clearFieldError, fieldError } from './components-b.js';

function tokenForm(platform: PlatformView, readOnly: boolean): HTMLFormElement {
  const form = element('form', undefined, 'screen-a-token-form'); form.autocomplete = 'off';
  form.setAttribute('aria-label', `Store ${platform.name} token`);
  const name = element('select'); name.name = 'name'; name.required = true;
  for (const token of [...platform.tokens].sort((a, b) => Number(b.recommended) - Number(a.recommended))) {
    const option = element('option', token.name); option.value = token.name; name.append(option);
  }
  const role = element('select'); role.name = 'role'; role.required = true;
  for (const value of ['read', 'write'] as const) {
    if (!platform.availableRoles.includes(value)) continue;
    const option = element('option', value === 'read' ? 'Read: scan and monitor' : 'Write: approved changes'); option.value = value; role.append(option);
  }
  const value = element('input'); value.type = 'password'; value.name = 'value'; value.autocomplete = 'one-time-code'; value.required = true;
  value.setAttribute('autocapitalize', 'off'); value.setAttribute('spellcheck', 'false');
  for (const [label, field] of [['Token name', name], ['Token role', role], ['Token value', value]] as const) {
    const wrapper = element('label', label); wrapper.append(field); form.append(wrapper);
    field.disabled = readOnly;
    field.addEventListener('invalid', () => fieldError(field, field === value ? 'Enter a token value.' : 'Choose a token name and role.'));
    field.addEventListener('input', () => clearFieldError(field)); field.addEventListener('change', () => clearFieldError(field));
  }
  const explanation = element('p', 'keysentry will store this token in your vault after passkey verification. The value is cleared from this form when you choose Store token.');
  const status = element('p'); status.setAttribute('role', 'status');
  const store = button('Store token'); store.type = 'submit';
  store.setAttribute('aria-label', `Store ${platform.name} token`);
  store.disabled = readOnly || name.options.length === 0 || role.options.length === 0;
  let pending = false;
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (readOnly || pending) { value.value = ''; return; }
    if (!name.value || !value.value || !platform.availableRoles.includes(role.value as 'read' | 'write')) {
      if (!name.value) fieldError(name, 'Choose a token name.');
      if (!value.value) fieldError(value, 'Enter a token value.');
      if (!platform.availableRoles.includes(role.value as 'read' | 'write')) fieldError(role, 'Choose an available token role.');
      return;
    }
    pending = true; store.disabled = true; status.textContent = 'Waiting for passkey verification.';
    const body = { name: name.value, role: role.value as 'read' | 'write', value: value.value };
    value.value = '';
    void (async () => {
      try {
        // The helper snapshots canonical JSON before its first await. Release our plaintext immediately.
        let request: Promise<{ stored: true }>;
        try { request = postWithPasskey<{ stored: true }>('vault/store', body); }
        finally { body.value = ''; }
        await request;
        status.textContent = 'Stored token.';
      } catch { status.textContent = 'Token was not stored. Enter it again and try Store token.'; }
      finally { body.value = ''; value.value = ''; pending = false; store.disabled = readOnly; }
    })();
  });
  form.append(explanation, store, status); return form;
}

export async function renderConnect(session: DashboardSession): Promise<HTMLElement> {
  const { platforms } = await get<{ platforms: PlatformView[] }>('platforms');
  const page = element('div', undefined, 'screen-a connect-screen');
  page.append(element('p', 'Choose the narrowest token for the platform you want to connect. Review what it can do before storing it.'));
  if (!platforms.length) { page.append(emptyState('No platforms are available to connect in this project. Run keysentry in your project folder to review its configuration.')); return page; }
  for (const platform of platforms) {
    const block = section(platform.name); block.dataset.platform = platform.host;
    block.append(element('p', platform.storedRoles.length ? 'Connected' : 'Not connected', 'screen-a-state'));
    if (platform.storedRoles.length) block.append(element('p', `Stored roles: ${platform.storedRoles.join(', ')}.`));
    block.append(element('p', platform.source === 'vault' ? 'Stored in the vault.' : platform.source === 'env' ? 'Provided by an environment variable.' : 'No token stored.', 'screen-a-muted'));
    for (const token of [...platform.tokens].sort((a, b) => Number(b.recommended) - Number(a.recommended))) {
      const details = element('section', undefined, 'screen-a-token');
      const title = element('h3'); title.append(element('code', token.name), document.createTextNode(token.recommended ? ' (recommended)' : ''));
      details.append(title, element('p', `Scope: ${token.scope}.`));
      const capability = token.canReadValues
        ? `read key values${token.canWrite ? ' and write keys' : ', but cannot write keys'}`
        : `${token.canWrite ? 'write keys' : 'list key names'}, but cannot read back key values`;
      details.append(element('p', `This token can ${capability}. keysentry will only ${platform.keysentryUses.scan} when scanning; it will only ${platform.keysentryUses.rotate} after you approve a change.`));
      const how = documentationLink(token.howToCreate);
      if (how) details.append(how);
      else details.append(element('p', 'Creation instructions are unavailable. Review the platform documentation before creating a token.'));
      details.append(element('p', `Source: ${token.source}`, 'screen-a-muted')); block.append(details);
    }
    block.append(tokenForm(platform, session.readOnly)); page.append(block);
  }
  return page;
}
