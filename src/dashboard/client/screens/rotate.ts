import { get, post, postWithPasskey } from '../api.js';
import type { DashboardSession } from '../api.js';
import { button, confirmAction, emptyState, table } from '../components.js';
import { actions, dateTime, el, field, input, lifetime, list, message, paragraph, scrollTable, section, status, taskButton } from './components-b.js';
import { providerName } from './components-a.js';

interface KeyChoice { id: string; provider: string; hint: string | null; method: string }
interface Preview { planId: string; planHash: string; changes: string[]; steps: { clusterId: string; hint: string | null; method: string; services: string[] }[]; warnings: string[] }
interface Rotation { planId: string; status?: string; startedAt: string; deadline?: string; steps: { clusterId: string; hint: string | null; status: string; warnings: string[] }[] }
interface Rotations { active: Rotation[] }

export async function renderRotate(session: DashboardSession): Promise<HTMLElement> {
  const [{ keys }, rotations] = await Promise.all([get<{ keys: KeyChoice[] }>('keys'), get<Rotations>('rotations')]);
  const root = el('div', undefined, 'screen-b'); const scope = lifetime(root); const feedback = status();
  const initialHash = location.hash; const live = () => !scope.signal.aborted && location.hash === initialHash;
  const selected = new Set<string>();
  const preselected = new URLSearchParams(location.hash.split('?')[1]).get('key');
  const choices = el('fieldset'); choices.append(el('legend', 'Choose keys'));
  for (const key of keys) {
    const choice = input(key.id, 'checkbox'); choice.checked = key.id === preselected; if (choice.checked) selected.add(key.id);
    choice.addEventListener('change', () => { if (choice.checked) selected.add(key.id); else selected.delete(key.id); });
    choices.append(field(`${providerName(key.provider)} · ${key.hint ?? 'Hint unavailable'} · ${key.method}`, choice));
  }
  if (!keys.length) choices.append(emptyState('No keys to rotate yet. Connect a platform and scan your keys.'));
  const previewDetail = el('div'); const progress = el('div'); let active = rotations.active; let progressSnapshot: string | undefined;
  const busyPlans = new Set<string>(); const graceControls = new Map<string, HTMLButtonElement[]>();
  const updateControls = () => { for (const [id, controls] of graceControls) for (const control of controls) control.disabled = session.readOnly || busyPlans.has(id); };
  const runGrace = async (id: string, action: () => Promise<void>) => {
    if (busyPlans.has(id) || scope.signal.aborted) return;
    busyPlans.add(id); updateControls();
    try { await action(); } finally { busyPlans.delete(id); updateControls(); }
  };
  let pollTimer: number | undefined; let clockTimer: number | undefined; let mounted = false; let refreshing = false;
  let clocks: (() => void)[] = [];
  const stopTimers = () => { if (pollTimer !== undefined) window.clearTimeout(pollTimer); if (clockTimer !== undefined) window.clearInterval(clockTimer); pollTimer = undefined; clockTimer = undefined; };
  const startClock = () => { if (mounted && clocks.length && clockTimer === undefined) clockTimer = window.setInterval(() => { for (const update of clocks) update(); }, 1_000); };
  scope.onDispose(stopTimers);
  const clock = (rotation: Rotation): HTMLElement => {
    const block = el('div', undefined, 'b-countdown'); const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 48 48'); svg.setAttribute('aria-hidden', 'true'); svg.classList.add('b-grace-ring');
    const circle = document.createElementNS(svg.namespaceURI, 'circle'); circle.setAttribute('cx', '24'); circle.setAttribute('cy', '24'); circle.setAttribute('r', '20'); circle.setAttribute('pathLength', '100'); svg.append(circle);
    const text = el('span'); const deadline = Date.parse(rotation.deadline!); const start = Date.parse(rotation.startedAt);
    const total = Math.max(1, deadline - start); let ringDrawn = false;
    const update = () => {
      const remaining = Math.max(0, deadline - Date.now()); const seconds = Math.ceil(remaining / 1000);
      const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      svg.classList.toggle('counting', remaining > 0 && Number.isFinite(remaining) && !reduced);
      if (!ringDrawn || !reduced) {
        circle.setAttribute('stroke-dasharray', '100'); circle.setAttribute('stroke-dashoffset', String(Number.isFinite(remaining) ? 100 * (1 - Math.min(1, remaining / total)) : 100)); ringDrawn = true;
      }
      text.textContent = !Number.isFinite(remaining) ? 'Grace deadline unavailable.' : seconds ? `${Math.floor(seconds / 60)}m ${String(seconds % 60).padStart(2, '0')}s remaining · ${dateTime(rotation.deadline)}` : `Grace deadline reached · ${dateTime(rotation.deadline)}. Check rotation status before revoking.`;
    };
    update(); clocks.push(update); block.append(svg, text); return block;
  };
  const showProgress = () => {
    const snapshot = JSON.stringify(active); if (snapshot === progressSnapshot) return; progressSnapshot = snapshot;
    const focused = document.activeElement instanceof HTMLElement && progress.contains(document.activeElement) ? document.activeElement : undefined;
    const focusedPlan = focused?.closest<HTMLElement>('[data-plan-id]')?.dataset.planId; const focusedLabel = focused?.textContent;
    clocks = []; graceControls.clear(); progress.replaceChildren();
    if (!active.length) { progress.append(emptyState('No rotation is active. Preview a rotation to see exactly what will change.')); return; }
    for (const rotation of active) {
      const block = section(`Rotation ${rotation.planId}`, paragraph(`Status: ${rotation.status ?? 'In progress'}. Started ${dateTime(rotation.startedAt)}.`));
      block.dataset.planId = rotation.planId;
      block.append(scrollTable(table(['Key', 'Status', 'Notes'], rotation.steps.map(step => [step.hint ?? 'Hint unavailable', step.status, step.warnings.join(' ')]), `Rotation progress for ${rotation.planId}`)));
      const timeline = el('a', 'View timeline'); timeline.href = `#activity?id=${encodeURIComponent(rotation.planId)}`; block.append(timeline);
      if (rotation.deadline) block.append(clock(rotation));
      if (rotation.status === 'grace-pending' && rotation.deadline) {
        const finish = taskButton('Revoke old keys now', feedback, () => runGrace(rotation.planId, async () => {
          if (!await confirmAction({ title: 'Revoke old keys now', changes: ['keysentry will revoke the old keys for this rotation before the grace deadline. Undo may no longer be available.'], button: 'Revoke old keys now', signal: scope.signal }) || scope.signal.aborted) return;
          await postWithPasskey('rotation/finish', { planId: rotation.planId, early: true }); if (!scope.signal.aborted) { message(feedback, 'Revocation requested', 'Check the rotation status below.'); await refresh(); }
        }), session.readOnly);
        const undo = taskButton('Undo', feedback, () => runGrace(rotation.planId, async () => {
          if (!await confirmAction({ title: 'Undo this rotation', changes: ['keysentry will restore the old keys where undo is still available.'], button: 'Undo', signal: scope.signal }) || scope.signal.aborted) return;
          const result = await postWithPasskey<{ restored: string[]; unavailable: { clusterId: string; reason: string }[] }>('rotation/undo', { planId: rotation.planId });
          if (!scope.signal.aborted) { message(feedback, 'Undo result', `${result.restored.length} keys restored.${result.unavailable.length ? ` ${result.unavailable.map(item => item.reason).join(' ')}` : ''}`, result.unavailable.length ? 'attention' : 'ok'); await refresh(); }
        }), session.readOnly);
        graceControls.set(rotation.planId, [finish, undo]);
        const later = button('Later', () => message(feedback, 'Grace period continues', 'The grace deadline stays the same. Return here to review the rotation.'), 'secondary');
        for (const control of [finish, undo, later]) control.setAttribute('aria-label', `${control.textContent} for rotation ${rotation.planId}`);
        block.append(paragraph('The old keys remain available during grace. Revoking early may remove the option to undo.'), actions(finish, undo, later));
      }
      progress.append(block);
    }
    updateControls(); startClock();
    if (focused) {
      const plan = [...progress.querySelectorAll<HTMLElement>('[data-plan-id]')].find(node => node.dataset.planId === focusedPlan);
      const replacement = [...(plan?.querySelectorAll<HTMLElement>('button, a') ?? [])].find(node => node.textContent === focusedLabel);
      if (replacement && !(replacement instanceof HTMLButtonElement && replacement.disabled)) replacement.focus();
      else { progress.tabIndex = -1; progress.focus(); }
    }
  };
  const schedule = () => {
    if (!mounted || !root.isConnected || !live() || !active.length || pollTimer !== undefined) return;
    pollTimer = window.setTimeout(() => { pollTimer = undefined; void refresh().catch(() => { if (!scope.signal.aborted) message(feedback, 'Status unavailable', 'The rotation status could not be refreshed. keysentry will try again.', 'attention'); }).finally(schedule); }, 3_000);
  };
  const refresh = async () => {
    if (!live() || refreshing) return;
    refreshing = true;
    try { const result = await get<Rotations>('rotations'); if (!scope.signal.aborted) { active = result.active; showProgress(); if (!active.length) stopTimers(); else schedule(); } }
    finally { refreshing = false; }
  };
  const preview = taskButton('Preview', feedback, async () => {
    if (!selected.size) { message(feedback, 'Choose keys', 'Choose at least one key to preview.', 'attention'); return; }
    const result = await post<Preview>('rotate/preview', { clusterIds: [...selected] }); if (scope.signal.aborted) return;
    previewDetail.replaceChildren(section('Rotation preview', list(result.changes), scrollTable(table(['Key', 'Method', 'Places'], result.steps.map(step => [step.hint ?? 'Hint unavailable', step.method, step.services.join(', ')]), 'Planned changes')), ...(result.warnings.length ? [section('Review before rotating', list(result.warnings))] : [])));
    const count = result.steps.length; const label = `Rotate ${count} ${count === 1 ? 'key' : 'keys'}`;
    if (!count) { message(feedback, 'No changes planned', 'Choose another key or review the plan warnings.'); return; }
    if (session.readOnly) { message(feedback, 'Read-only preview', 'This preview does not change keys. Open keysentry ui in your terminal to rotate them.'); return; }
    if (!await confirmAction({ title: 'Confirm rotation', changes: result.changes, button: label, signal: scope.signal }) || scope.signal.aborted) return;
    await postWithPasskey('rotate/execute', { planId: result.planId, planHash: result.planHash });
    if (!scope.signal.aborted) { message(feedback, 'Rotation requested', 'Check progress and the grace deadline below.'); await refresh(); }
  });
  const drill = taskButton('Run a drill', feedback, async () => {
    const result = await post<{ score: number; reasons: string[] }>('drill', {});
    if (!scope.signal.aborted) message(feedback, 'Drill complete', `Readiness ${result.score}/100. ${result.reasons.join(' ')}`, 'ok');
  });
  showProgress(); root.append(paragraph('Preview the exact changes before rotating. A drill checks readiness without changing keys.'), choices, actions(preview, drill), feedback, previewDetail, section('Rotation progress', progress));
  scope.onMount(() => { mounted = true; schedule(); startClock(); });
  return root;
}
