import { get, post, postWithPasskey } from '../api.js';
import type { DashboardSession } from '../api.js';
import { confirmAction, emptyState, table } from '../components.js';
import { actions, dateTime, el, field, input, lifetime, list, message, numberInput, paragraph, scrollTable, section, status, taskButton, validNumber } from './components-b.js';
import { hostName, providerName } from './components-a.js';

interface Autopilot {
  state: 'off' | 'armed' | 'alert-only' | 'disarmed'; reasons: string[];
  plan?: { id: string; keys: number; hosts: string[]; expiresAt: string; graceMinutes: number };
  waves: { id: string; incident: string; status: string; deadline?: string }[];
  lastNotificationAt: string | null; needsRefresh: boolean;
}
interface Eligibility {
  eligible: { id: string; hint: string | null; provider: string; needsAdoption: boolean }[];
  ineligible: { id: string; hint: string | null; reason: string }[]; lastDrillAt: string | null;
}
interface ArmResult { planId: string; expiresAt: string; refused: { id: string; reason: string }[] }
interface Coordination {
  arming?: Promise<ArmResult>; offGeneration: number; turningOff: boolean;
  listeners: Set<(state?: Autopilot) => void>;
}
// Keep unfinished arm/disarm ordering across route changes within this session.
const sessions = new WeakMap<DashboardSession, Coordination>();
function coordinationFor(session: DashboardSession): Coordination {
  let coordination = sessions.get(session);
  if (!coordination) { coordination = { offGeneration: 0, turningOff: false, listeners: new Set() }; sessions.set(session, coordination); }
  return coordination;
}

export async function renderAutopilot(session: DashboardSession): Promise<HTMLElement> {
  const [initial, eligibility] = await Promise.all([get<Autopilot>('autopilot'), get<Eligibility>('autopilot/eligibility')]);
  const root = el('div', undefined, 'screen-b'); const scope = lifetime(root); const feedback = status();
  let state = initial; let lastDrillAt = eligibility.lastDrillAt;
  const coordination = coordinationFor(session);
  const notify = (updated?: Autopilot) => { for (const listener of coordination.listeners) listener(updated); };
  const stateText = paragraph(''); const stateNotes = el('div');
  const describe = () => {
    if (coordination.turningOff) stateText.textContent = 'Autopilot is turning off while an earlier request finishes.';
    else if (state.state === 'armed' && state.plan) {
      const expiry = new Date(state.plan.expiresAt); const until = Number.isFinite(expiry.getTime()) ? expiry.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : 'its expiry';
      stateText.textContent = `Autopilot is armed for ${state.plan.keys} ${state.plan.keys === 1 ? 'key' : 'keys'} on ${state.plan.hosts.map(hostName).join(' and ')} until ${until}.`;
    } else stateText.textContent = { off: 'Autopilot is off.', armed: 'Autopilot is armed; scope details are unavailable.', 'alert-only': 'Autopilot is in alert-only mode.', disarmed: 'Autopilot is disarmed.' }[state.state];
    stateNotes.replaceChildren(...(state.reasons.length ? [list(state.reasons)] : []));
    if (state.needsRefresh) stateNotes.append(paragraph('The armed plan needs a refresh. Review the key choices and run a drill before arming again.'));
  };
  describe();
  const chosen = new Map<string, HTMLInputElement>(); const adoptions = new Map<string, HTMLInputElement>();
  const rows: (string | Node)[][] = eligibility.eligible.map(key => {
    const choose = input(key.id, 'checkbox'); choose.disabled = session.readOnly; chosen.set(key.id, choose);
    const identity = field(`${providerName(key.provider)} · ${key.hint ?? 'Hint unavailable'}`, choose); choose.addEventListener('change', () => updateArm());
    let consent: Node = el('span', 'No adoption needed');
    if (key.needsAdoption) {
      const adopt = input(`adopt-${key.id}`, 'checkbox'); adopt.disabled = session.readOnly; adoptions.set(key.id, adopt);
      adopt.addEventListener('change', () => { if (adopt.checked) choose.checked = true; updateArm(); });
      consent = field('This rotates the key now so keysentry can rotate it automatically later', adopt);
    }
    return [identity, key.needsAdoption ? 'Needs adoption' : 'Eligible', consent];
  });
  rows.push(...eligibility.ineligible.map(key => [key.hint ?? 'Hint unavailable', 'Not eligible', key.reason]));
  const grace = numberInput('graceMinutes', state.plan?.graceMinutes ?? 15, 0, Math.floor(Number.MAX_SAFE_INTEGER / 60));
  const maxServices = numberInput('maxServices', 10, 1); const validDays = numberInput('validDays', 90, 1, 365);
  for (const control of [grace, maxServices, validDays]) control.disabled = session.readOnly;
  const recent = () => { const at = Date.parse(lastDrillAt ?? ''); const age = Date.now() - at; return Number.isFinite(at) && age >= 0 && age < 86_400_000; };
  const drillNote = paragraph(''); let expiryTimer: number | undefined;
  const arm = taskButton('Arm autopilot', feedback, async () => {
    const armGeneration = coordination.offGeneration;
    const clusterIds = [...chosen].filter(([, choice]) => choice.checked).map(([id]) => id);
    const adopt = [...adoptions].filter(([id, choice]) => choice.checked && chosen.get(id)?.checked).map(([id]) => id);
    const graceMinutes = validNumber(grace, 0, Math.floor(Number.MAX_SAFE_INTEGER / 60), false);
    const maximum = validNumber(maxServices, 1); const days = validNumber(validDays, 1, 365);
    if (!recent()) { updateArm(); message(feedback, 'Run a drill first', 'Arming needs a drill from the last 24 hours.', 'attention'); return; }
    if (!clusterIds.length || clusterIds.some(id => adoptions.has(id) && !adopt.includes(id))) { message(feedback, 'Review key choices', 'Choose at least one key. For each key that needs adoption, agree to rotate it now or leave it unselected.', 'attention'); return; }
    if (graceMinutes === null || maximum === null || days === null) { message(feedback, 'Check the numbers', 'Use a nonnegative grace period, a positive whole number of services, and 1 to 365 days.', 'attention'); return; }
    const changes = [`keysentry will arm autopilot for ${clusterIds.length} ${clusterIds.length === 1 ? 'key' : 'keys'} for ${days} days, with up to ${maximum} services per wave and ${graceMinutes} minutes of grace.`];
    for (const id of adopt) { const key = eligibility.eligible.find(item => item.id === id)!; changes.push(`This rotates ${providerName(key.provider)} ${key.hint ?? '(hint unavailable)'} now so keysentry can rotate it automatically later.`); }
    if (!await confirmAction({ title: 'Arm autopilot', changes, button: 'Arm autopilot', signal: scope.signal }) || scope.signal.aborted || armGeneration !== coordination.offGeneration || coordination.turningOff) return;
    // The confirmation and passkey can take time; the server also checks the last drill.
    if (!recent()) { updateArm(); message(feedback, 'Run another drill', 'The last drill is now more than 24 hours old.', 'attention'); return; }
    const pending = postWithPasskey<ArmResult>('autopilot/arm', { clusterIds, adopt, graceMinutes, maxServices: maximum, validDays: days }); coordination.arming = pending; notify();
    let result: ArmResult;
    try { result = await pending; } finally { if (coordination.arming === pending) coordination.arming = undefined; notify(); }
    if (armGeneration !== coordination.offGeneration) return;
    if (!scope.signal.aborted) message(feedback, result.refused.length ? 'Review arming result' : 'Autopilot armed', result.refused.length ? result.refused.map(item => item.reason).join(' ') : `Armed until ${dateTime(result.expiresAt)}.`, result.refused.length ? 'attention' : 'ok');
    if (coordination.listeners.size) {
      const updated = await get<Autopilot>('autopilot'); if (armGeneration === coordination.offGeneration) notify(updated);
    }
  }, () => session.readOnly || coordination.turningOff || !!coordination.arming || !recent() || ![...chosen.values()].some(choice => choice.checked));
  const updateArm = () => { arm.disabled = session.readOnly || coordination.turningOff || !!coordination.arming || !recent() || ![...chosen.values()].some(choice => choice.checked); drillNote.textContent = recent() ? `Last drill: ${dateTime(lastDrillAt)}. Arming needs a drill from the last 24 hours.` : 'Run a drill before arming. The drill must be from the last 24 hours.'; };
  let disarmControl: HTMLButtonElement | undefined;
  const changed = (updated?: Autopilot) => { if (updated) state = updated; describe(); updateArm(); if (disarmControl) disarmControl.disabled = coordination.turningOff; };
  coordination.listeners.add(changed); scope.onDispose(() => coordination.listeners.delete(changed));
  const scheduleExpiry = () => {
    if (expiryTimer !== undefined) window.clearTimeout(expiryTimer);
    if (recent()) expiryTimer = window.setTimeout(updateArm, Math.max(1, Date.parse(lastDrillAt!) + 86_400_000 - Date.now()));
  };
  scope.onDispose(() => { if (expiryTimer !== undefined) window.clearTimeout(expiryTimer); });
  scope.onMount(scheduleExpiry);
  const drill = taskButton('Run a drill', feedback, async () => {
    const result = await post<{ score: number; reasons: string[]; elapsedMs: number }>('drill', {}); if (scope.signal.aborted) return;
    lastDrillAt = new Date().toISOString(); updateArm(); scheduleExpiry();
    message(feedback, 'Drill complete', `Readiness ${result.score}/100. ${result.reasons.join(' ')}`, 'ok');
  });
  const disarm = taskButton('Turn off autopilot', feedback, async () => {
    if (!await confirmAction({ title: 'Turn off autopilot', changes: ['keysentry will stop starting automatic rotations. Rotations already in progress keep their current status.'], button: 'Turn off autopilot', signal: scope.signal }) || scope.signal.aborted) return;
    ++coordination.offGeneration; coordination.turningOff = true; notify(); const pending = coordination.arming;
    try {
      let result = await post<{ state: 'disarmed' }>('autopilot/disarm', {});
      if (pending) {
        if (!scope.signal.aborted) { stateText.textContent = 'Autopilot is turning off while an earlier arming request finishes.'; message(feedback, 'Turning off autopilot', 'The current plan is disarmed. keysentry will turn it off again when the earlier arming request finishes.'); }
        // The passkey helper cannot cancel an assertion already in flight. Disarm immediately,
        // then repeat after that exact request settles so an earlier arm cannot be the last write.
        await pending.catch(() => {});
        result = await post<{ state: 'disarmed' }>('autopilot/disarm', {});
      }
      state = { ...state, state: result.state, reasons: [], needsRefresh: false }; notify(state);
      if (!scope.signal.aborted) message(feedback, 'Autopilot disarmed', 'Automatic rotations are turned off.', 'ok');
    } finally { coordination.turningOff = false; notify(); }
  }, () => coordination.turningOff);
  disarmControl = disarm;
  updateArm();
  root.append(stateText, stateNotes, paragraph(`Last successful notification: ${dateTime(state.lastNotificationAt)}.`),
    section('Keys for autopilot', rows.length ? scrollTable(table(['Key', 'Eligibility', 'Reason or adoption choice'], rows, 'Autopilot eligibility')) : emptyState('No eligible keys yet. Connect a platform and scan your keys.')),
    section('Arm autopilot', paragraph('A drill checks readiness without changing keys. Arming allows automatic rotations within the chosen scope. Adoption performs a rotation now for each key you select for adoption.'), drillNote,
      field('Grace period (minutes)', grace), field('Maximum services per wave', maxServices), field('Plan validity (days)', validDays), actions(drill, arm, disarm)), feedback,
    section('Waves', state.waves.length ? scrollTable(table(['Incident', 'Status', 'Deadline', 'Timeline'], state.waves.map(wave => {
      const link = el('a', 'Timeline'); link.href = `#activity?id=${encodeURIComponent(wave.id)}`;
      return [wave.incident, wave.status, dateTime(wave.deadline), link];
    }), 'Autopilot waves')) : emptyState('No autopilot waves yet.')));
  return root;
}
