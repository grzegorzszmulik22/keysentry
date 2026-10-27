import { get, post, postWithPasskey, type DashboardSession } from '../api.js';
import { confirmAction, emptyState, table } from '../components.js';
import { actions, el, field, fieldError, input, lifetime, message, paragraph, scrollTable, status, taskButton } from './components-b.js';

type NotifyChannelKind = 'telegram' | 'discord' | 'slack' | 'ntfy' | 'webhook' | 'resend' | 'smtp' | 'console';
interface Channel { id: string; kind: NotifyChannelKind; label: string; lastSuccessAt: string | null }
interface Channels { channels: Channel[]; deviceKeyId: string }
interface ConfigField { name: string; label: string; secret?: boolean; optional?: boolean; value?: string }
const kinds: Record<NotifyChannelKind, { label: string; fields: ConfigField[] }> = {
  telegram: { label: 'Telegram', fields: [{ name: 'botToken', label: 'Bot token', secret: true }, { name: 'chatId', label: 'Chat ID' }] },
  discord: { label: 'Discord', fields: [{ name: 'webhookUrl', label: 'Webhook URL', secret: true }] },
  slack: { label: 'Slack', fields: [{ name: 'webhookUrl', label: 'Webhook URL', secret: true }] },
  ntfy: { label: 'ntfy', fields: [{ name: 'server', label: 'Server', value: 'https://ntfy.sh' }, { name: 'topic', label: 'Topic' }, { name: 'token', label: 'Access token (optional)', secret: true, optional: true }] },
  webhook: { label: 'Webhook', fields: [{ name: 'url', label: 'Webhook URL', secret: true }] },
  resend: { label: 'Resend', fields: [{ name: 'apiKey', label: 'API key', secret: true }, { name: 'from', label: 'From address' }, { name: 'to', label: 'To address' }] },
  smtp: { label: 'SMTP', fields: [{ name: 'host', label: 'Mail server' }, { name: 'port', label: 'Port (465 or 587)', value: '465' }, { name: 'username', label: 'Username' }, { name: 'password', label: 'Password', secret: true }, { name: 'from', label: 'From address' }, { name: 'to', label: 'To address' }] },
  console: { label: 'Console', fields: [] },
};

/** Channel responses contain metadata only; credentials exist only in the add request. */
export async function renderNotifications(session: DashboardSession): Promise<HTMLElement> {
  const root = el('div', undefined, 'screen-b');
  const life = lifetime(root);
  let data = await get<Channels>('notifications');
  if (life.signal.aborted) return root;
  const feedback = status();
  const channelList = el('section');
  const refresh = async () => {
    const next = await get<Channels>('notifications');
    if (!life.signal.aborted) { data = next; drawChannels(); }
  };
  const drawChannels = () => {
    channelList.replaceChildren(el('h2', 'Channels'));
    if (!data.channels.length) { channelList.append(emptyState('Add a channel to receive signed messages from keysentry.')); return; }
    channelList.append(scrollTable(table(['Channel', 'Kind', 'Last successful delivery', 'Action'], data.channels.map(channel => {
      const remove = taskButton('Remove', feedback, async () => {
        if (!await confirmAction({ title: 'Remove channel', changes: [`keysentry will stop sending notifications to ${channel.label}.`], button: 'Remove', signal: life.signal })) return;
        if (life.signal.aborted) return;
        const result = await postWithPasskey<{ removed: boolean }>('notifications/remove', { id: channel.id });
        if (life.signal.aborted) return;
        if (result.removed) {
          data.channels = data.channels.filter(item => item.id !== channel.id); drawChannels();
          message(feedback, 'Channel removed', 'keysentry will no longer send notifications to this channel.', 'ok');
        } else message(feedback, 'Channel unchanged', 'The channel was not removed. Refresh the page and try again.', 'attention');
      }, session.readOnly);
      const duplicate = data.channels.some(item => item.id !== channel.id && item.label === channel.label && item.kind === channel.kind);
      remove.setAttribute('aria-label', `Remove ${channel.label} (${channel.kind})${duplicate ? `, ${channel.id}` : ''}`);
      return [channel.label, kinds[channel.kind]?.label ?? channel.kind, channel.lastSuccessAt ? new Date(channel.lastSuccessAt).toLocaleString() : 'No successful delivery yet', remove];
    }), 'Notification channels')));
  };
  drawChannels();

  const testAll = taskButton('Test all channels', feedback, async () => {
    if (life.signal.aborted) return;
    const result = await postWithPasskey<{ delivered: string[]; failed: { id: string; reason: string }[] }>('notifications/test', {});
    if (life.signal.aborted) return;
    await refresh();
    if (life.signal.aborted) return;
    message(feedback, 'Channels tested', `${result.delivered.length} delivered; ${result.failed.length} could not be delivered.${result.failed.length ? ' Check the channel settings and try again.' : ''}`, result.failed.length ? 'attention' : 'ok');
  }, session.readOnly);
  root.append(paragraph('Messages are signed by your device. Adding or removing a channel changes where future notifications are sent.'), channelList,
    paragraph('Test all channels sends one test message to every configured channel.'), actions(testAll));

  const form = el('form', undefined, 'b-form');
  form.addEventListener('submit', event => event.preventDefault());
  const kind = el('select'); kind.name = 'kind'; kind.disabled = session.readOnly;
  for (const [id, definition] of Object.entries(kinds)) { const option = el('option', definition.label); option.value = id; kind.append(option); }
  const label = input('label', 'text'); label.required = true; label.maxLength = 120; label.disabled = session.readOnly;
  const config = el('div', undefined, 'b-form');
  let fields: { definition: ConfigField; control: HTMLInputElement }[] = [];
  const clearSecrets = () => { for (const item of fields) if (item.definition.secret) item.control.value = ''; };
  const drawFields = () => {
    clearSecrets(); fields = []; config.replaceChildren();
    for (const definition of kinds[kind.value as NotifyChannelKind].fields) {
      const control = input(definition.name, definition.secret ? 'password' : 'text', definition.value ?? '');
      control.required = !definition.optional; control.autocomplete = definition.secret ? 'one-time-code' : 'off'; control.disabled = session.readOnly;
      if (definition.secret) { control.setAttribute('autocapitalize', 'off'); control.setAttribute('spellcheck', 'false'); }
      if (definition.name === 'port') { control.inputMode = 'numeric'; control.pattern = '465|587'; }
      fields.push({ definition, control }); config.append(field(definition.label, control));
    }
  };
  kind.addEventListener('change', drawFields); drawFields(); life.onDispose(clearSecrets);
  const add = taskButton('Add channel', feedback, async () => {
    if (!form.reportValidity() || life.signal.aborted) return;
    const settings: Record<string, string> = {};
    for (const item of fields) if (item.control.value || !item.definition.optional) settings[item.definition.name] = item.control.value;
    const body = { kind: kind.value as NotifyChannelKind, label: label.value.trim(), settings };
    clearSecrets();
    if (!body.label) { fieldError(label, 'Enter a short name you will recognize.'); message(feedback, 'Choose a channel label', 'Enter a short name you will recognize.', 'attention'); return; }
    // The shared helper snapshots canonical request bytes before its first await.
    // Release the screen's temporary credential copies while the passkey prompt is open.
    const request = postWithPasskey('notifications/add', body);
    for (const item of fields) if (item.definition.secret) settings[item.definition.name] = '';
    await request;
    if (life.signal.aborted) return;
    await refresh();
    if (!life.signal.aborted) message(feedback, 'Channel added', 'Future notifications will include this channel. Test it to check delivery.', 'ok');
  }, session.readOnly);
  add.type = 'submit';
  form.append(el('h2', 'Add a channel'), paragraph('keysentry will store these channel settings for future notifications. Credentials are sent only when you choose Add channel and verify with your passkey.'), field('Kind', kind), field('Channel label', label), config, actions(add));

  const verify = el('form', undefined, 'b-form'); verify.addEventListener('submit', event => event.preventDefault());
  const code = input('code', 'text'); code.required = true; code.autocomplete = 'off';
  const check = taskButton('Check a message', feedback, async () => {
    if (!verify.reportValidity() || life.signal.aborted) return;
    const result = await post<{ valid: boolean; message: string }>('notifications/verify', { code: code.value.trim() });
    if (!life.signal.aborted) message(feedback, result.valid ? 'Message verified' : 'Message not verified', result.message, result.valid ? 'ok' : 'attention');
  }); check.type = 'submit';
  verify.append(el('h2', 'Check a message'), paragraph('Enter the verification code from a notification to check its signature.'), field('Verification code', code), actions(check));
  root.append(form, verify, feedback); return root;
}
