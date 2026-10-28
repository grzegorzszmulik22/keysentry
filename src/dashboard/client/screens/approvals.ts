import { get, postWithPasskey } from '../api.js';
import type { DashboardSession } from '../api.js';
import { confirmAction, emptyState } from '../components.js';
import { actions, dateTime, el, lifetime, message, paragraph, section, status, taskButton } from './components-b.js';

interface Pending {
  id: string; kind: string; summary: string; changes: string[]; reviewHash: string; createdAt: string; expiresAt?: string; source: 'monitor' | 'autopilot';
  /** Team mode: distinct team approvals so far and how many the team policy needs. */
  quorum?: { approvals: number; required: number };
}
interface ApproveResult { result?: string; text?: string; approvals?: number; required?: number }

function progress(quorum: { approvals: number; required: number }): string {
  return `${quorum.approvals} of ${quorum.required} team approvals so far.`;
}

export async function renderApprovals(session: DashboardSession): Promise<HTMLElement> {
  const { pending } = await get<{ pending: Pending[] }>('approvals'); const root = el('div', undefined, 'screen-b'); const scope = lifetime(root); const feedback = status();
  root.append(paragraph('Review the exact action before approving or dismissing it. Each choice needs your passkey.'), feedback);
  if (!pending.length) root.append(emptyState('No approvals waiting. New requests will appear here when a decision is needed.'));
  const expiries: { deadline: number; controls: HTMLButtonElement[]; label: HTMLElement; pending(): boolean }[] = [];
  for (const item of pending) {
    const deadline = item.expiresAt ? Date.parse(item.expiresAt) : Infinity; let completed = false;
    const expired = () => !Number.isFinite(deadline) && deadline !== Infinity || Date.now() >= deadline;
    const state = paragraph(expired() ? 'Expired' : 'Pending');
    const identity = `${item.summary} (${item.id})`;
    const block = section(identity, paragraph(`${item.kind} · From ${item.source} · Created ${dateTime(item.createdAt)}.${item.expiresAt ? ` Expires ${dateTime(item.expiresAt)}.` : ''}`), state);
    const count = item.quorum ? paragraph(progress(item.quorum)) : undefined;
    if (count) block.append(count);
    const decide = async (decision: 'approve' | 'dismiss') => {
      if (expired()) { state.textContent = 'Expired'; return; }
      const label = decision === 'approve' ? 'Approve' : 'Dismiss';
      const changes = decision === 'approve' ? item.changes : [item.summary, 'keysentry will dismiss this request.'];
      if (!await confirmAction({ title: `${label} request`, changes, button: label, signal: scope.signal }) || scope.signal.aborted) return;
      if (expired()) { state.textContent = 'Expired'; return; }
      const body = decision === 'approve' ? { id: item.id, reviewHash: item.reviewHash } : { id: item.id };
      const result = await postWithPasskey<ApproveResult>(`approvals/${decision}`, body); if (scope.signal.aborted) return;
      if (decision === 'approve' && result.result === 'recorded') {
        // A team approval was recorded; more members must approve. This is progress, not a failure.
        const quorum = { approvals: result.approvals ?? 0, required: result.required ?? 0 };
        completed = true; state.textContent = 'Waiting for more team approvals'; controls.remove();
        if (count) count.textContent = progress(quorum); else block.append(paragraph(progress(quorum)));
        message(feedback, 'Approval recorded', result.text ?? progress(quorum), 'ok');
        return;
      }
      completed = true; state.textContent = decision === 'approve' ? 'Approved' : 'Dismissed'; controls.remove();
      message(feedback, state.textContent, decision === 'approve' ? result.result ?? 'This action was approved.' : 'This request was dismissed.', 'ok');
    };
    const approve = taskButton('Approve', feedback, async () => { approve.disabled = true; dismiss.disabled = true; try { await decide('approve'); } finally { if (controls.isConnected) dismiss.disabled = session.readOnly || expired(); } }, () => session.readOnly || expired() || completed);
    const dismiss = taskButton('Dismiss', feedback, async () => { approve.disabled = true; dismiss.disabled = true; try { await decide('dismiss'); } finally { if (controls.isConnected) approve.disabled = session.readOnly || expired(); } }, () => session.readOnly || expired() || completed);
    approve.setAttribute('aria-label', `Approve ${identity}`); dismiss.setAttribute('aria-label', `Dismiss ${identity}`);
    const controls = actions(approve, dismiss); block.append(controls); root.append(block);
    if (!expired() && deadline !== Infinity) expiries.push({ deadline, controls: [approve, dismiss], label: state, pending: () => !completed });
  }
  let timer: number | undefined;
  const check = () => { for (const item of expiries) if (item.pending() && Date.now() >= item.deadline) { item.label.textContent = 'Expired'; for (const control of item.controls) control.disabled = true; } };
  scope.onMount(() => { if (expiries.length) timer = window.setInterval(check, 1_000); });
  scope.onDispose(() => { if (timer !== undefined) window.clearInterval(timer); });
  return root;
}
