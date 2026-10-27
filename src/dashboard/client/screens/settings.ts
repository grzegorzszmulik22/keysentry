import { get, postWithPasskey, type DashboardSession } from '../api.js';
import { button } from '../components.js';
import { actions, el, field, input, lifetime, message, paragraph, status, taskButton } from './components-b.js';

interface Settings {
  graceMinutes: number; rotateEveryDays: number; spendCapsUsd: Record<string, number>;
  digestDay: 'mon' | 'tue' | 'wed' | 'thu' | 'fri' | 'sat' | 'sun' | 'off'; showHints: boolean;
}

export async function renderSettings(session: DashboardSession): Promise<HTMLElement> {
  const root = el('div', undefined, 'screen-b'); const life = lifetime(root);
  const current = await get<Settings>('settings'); if (life.signal.aborted) return root;
  const feedback = status(); const form = el('form', undefined, 'b-form'); form.addEventListener('submit', event => event.preventDefault());
  const grace = input('graceMinutes', 'number', String(current.graceMinutes)); grace.min = '0'; grace.step = 'any'; grace.required = true;
  const rotate = input('rotateEveryDays', 'number', String(current.rotateEveryDays)); rotate.min = '1'; rotate.max = '36500'; rotate.step = '1'; rotate.required = true;
  const digest = el('select'); digest.name = 'digestDay';
  for (const [value, label] of [['off', 'Off'], ['mon', 'Monday'], ['tue', 'Tuesday'], ['wed', 'Wednesday'], ['thu', 'Thursday'], ['fri', 'Friday'], ['sat', 'Saturday'], ['sun', 'Sunday']]) {
    const option = el('option', label); option.value = value!; digest.append(option);
  }
  digest.value = current.digestDay;
  const hints = input('showHints', 'checkbox'); hints.checked = current.showHints;
  for (const control of [grace, rotate, digest, hints]) control.disabled = session.readOnly;
  const capList = el('div', undefined, 'b-form');
  const caps: { name: HTMLInputElement; amount: HTMLInputElement; row: HTMLElement }[] = [];
  const addCap = (name = '', amount = '') => {
    const row = el('div', undefined, 'b-cap-row');
    const provider = input('spendCapKey', 'text', name); provider.required = true; provider.disabled = session.readOnly;
    const value = input('spendCapUsd', 'number', amount); value.required = true; value.min = '0'; value.step = 'any'; value.disabled = session.readOnly;
    const item = { name: provider, amount: value, row }; caps.push(item);
    const remove = button('Remove cap', () => { const index = caps.indexOf(item); if (index >= 0) caps.splice(index, 1); row.remove(); }, 'secondary'); remove.disabled = session.readOnly;
    row.append(field('Provider or key', provider), field('Spend cap (USD)', value), remove); capList.append(row);
  };
  for (const [key, value] of Object.entries(current.spendCapsUsd)) addCap(key, String(value));
  const add = button('Add spend cap', () => addCap(), 'secondary'); add.disabled = session.readOnly;
  const save = taskButton('Save settings', feedback, async () => {
    if (life.signal.aborted) return;
    const graceMinutes = Number(grace.value); const rotateEveryDays = Number(rotate.value);
    const values: [string, number][] = []; const names = new Set<string>();
    let valid = grace.value !== '' && Number.isFinite(graceMinutes) && graceMinutes >= 0 && Number.isSafeInteger(graceMinutes * 60)
      && rotate.value !== '' && Number.isInteger(rotateEveryDays) && rotateEveryDays >= 1 && rotateEveryDays <= 36500;
    for (const cap of caps) {
      const name = cap.name.value.trim(); const amount = Number(cap.amount.value);
      if (!name || names.has(name) || cap.amount.value === '' || !Number.isFinite(amount) || amount < 0) valid = false;
      names.add(name); values.push([name, amount]);
    }
    if (!valid || !form.reportValidity()) {
      message(feedback, 'Review the numbers', 'Use a nonnegative grace period in whole seconds, a whole rotation interval from 1 to 36500 days, and nonnegative spend caps with unique names.', 'attention'); return;
    }
    const body: Settings = { graceMinutes, rotateEveryDays, spendCapsUsd: Object.fromEntries(values), digestDay: digest.value as Settings['digestDay'], showHints: hints.checked };
    await postWithPasskey<Settings>('settings/update', body);
    if (!life.signal.aborted) message(feedback, 'Settings saved', 'These settings will be used for future plans, reminders and notifications.', 'ok');
  }, session.readOnly); save.type = 'submit';
  form.append(paragraph('Saving changes the defaults for future plans, rotation reminders, spend caps and the weekly digest. Existing armed plans keep their signed settings.'),
    field('Grace period (minutes)', grace), field('Rotate every (days)', rotate), field('Weekly digest', digest), field('Include key hints in notifications', hints),
    el('h2', 'Spend caps'), paragraph('Spend caps are saved here. Applying a provider limit is a separate action where supported.'), capList, actions(add), actions(save));
  root.append(form, feedback); return root;
}
