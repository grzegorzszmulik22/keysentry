import { postWithPasskey } from './api.js';

/**
 * Team dashboard: true when a change was recorded as a team request that still needs other members' approvals (the
 * api's TeamRequestRecorded). Matched by name, so screens need not import the class.
 */
export function isTeamRequestRecorded(error: unknown): error is Error {
  return error instanceof Error && error.name === 'TeamRequestRecorded';
}

export function button(label: string, onClick?: () => void, variant: 'primary' | 'secondary' | 'danger' = 'primary'): HTMLButtonElement {
  const control = document.createElement('button'); control.type = 'button'; control.className = `button ${variant}`; control.textContent = label;
  if (onClick) control.addEventListener('click', onClick);
  return control;
}

export interface KeyTagData { provider: string; hint: string | null; state?: string; copies?: number; ageDays?: number; inGitHistory?: boolean }

export function keyTag(key: KeyTagData, onOpen?: () => void): HTMLButtonElement {
  const tag = button('', onOpen); tag.className = 'key-tag';
  const provider = document.createElement('span'); provider.className = 'key-tag-provider'; provider.textContent = key.provider;
  const hint = document.createElement('code'); hint.className = 'key-tag-hint'; hint.textContent = key.hint ?? 'Hint unavailable';
  const metadata = document.createElement('span'); metadata.className = 'key-tag-meta';
  metadata.textContent = [key.copies === undefined ? '' : `${key.copies} ${key.copies === 1 ? 'place' : 'places'}`, key.ageDays === undefined ? '' : `${key.ageDays} ${key.ageDays === 1 ? 'day' : 'days'}`].filter(Boolean).join(' · ');
  const state = document.createElement('span'); state.className = 'key-tag-state'; state.textContent = key.state ?? (key.inGitHistory ? 'In git history' : 'Not checked');
  tag.append(provider, hint, metadata, state);
  return tag;
}

export function notice(kind: 'ok' | 'attention' | 'stop' | 'info', title: string, text: string): HTMLElement {
  const block = document.createElement('section'); block.className = `notice notice-${kind}`;
  const state = document.createElement('span'); state.className = 'notice-status'; state.textContent = { ok: 'Complete', attention: 'Needs attention', stop: 'Stopped', info: 'Information' }[kind];
  const heading = document.createElement('h2'); heading.textContent = title;
  const copy = document.createElement('p'); copy.textContent = text;
  block.append(state, heading, copy); return block;
}

export function table(columns: string[], rows: (string | Node)[][], caption = 'Details'): HTMLTableElement {
  const element = document.createElement('table'); element.className = 'data-table';
  const label = element.createCaption(); label.textContent = caption;
  const head = element.createTHead().insertRow();
  for (const column of columns) { const cell = document.createElement('th'); cell.scope = 'col'; cell.textContent = column; head.append(cell); }
  const body = element.createTBody();
  for (const row of rows) { const line = body.insertRow(); for (const content of row) { const cell = line.insertCell(); if (typeof content === 'string') cell.textContent = content; else cell.append(content); } }
  return element;
}

export function emptyState(text: string, action?: { label: string; onClick(): void }): HTMLElement {
  const block = document.createElement('section'); block.className = 'empty-state';
  const copy = document.createElement('p'); copy.textContent = text; block.append(copy);
  if (action) block.append(button(action.label, action.onClick));
  return block;
}

let dialogId = 0;
export function confirmAction(input: { title: string; changes: string[]; button: string; signal?: AbortSignal }): Promise<boolean> {
  const previous = document.activeElement;
  const dialog = document.createElement('dialog'); dialog.className = 'confirm-dialog';
  const heading = document.createElement('h2'); heading.id = `confirm-action-${++dialogId}`; heading.textContent = input.title; dialog.setAttribute('aria-labelledby', heading.id);
  const changes = document.createElement('ul');
  for (const change of input.changes) { const line = document.createElement('li'); line.textContent = change; changes.append(line); }
  const actions = document.createElement('div'); actions.className = 'dialog-actions';
  return new Promise(resolve => {
    let completed = false;
    const finish = (accepted: boolean) => {
      if (completed) return; completed = true;
      input.signal?.removeEventListener('abort', abort);
      if (dialog.open) dialog.close(); dialog.remove();
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus();
      resolve(accepted);
    };
    const abort = () => finish(false);
    const cancel = button('Cancel', () => finish(false), 'secondary');
    actions.append(cancel, button(input.button, () => finish(true)));
    dialog.append(heading, changes, actions);
    dialog.addEventListener('cancel', event => { event.preventDefault(); finish(false); });
    dialog.addEventListener('close', () => finish(false));
    if (input.signal?.aborted) { finish(false); return; }
    input.signal?.addEventListener('abort', abort, { once: true });
    document.body.append(dialog); dialog.showModal(); cancel.focus();
  });
}

let clipboardClearTimer: number | undefined;
let clipboardCopyGeneration = 0;
const componentDisposers = new WeakMap<HTMLElement, () => void>();

/** The router calls this before removing a page, including pages retained by a screen. */
export function disposeComponents(root: ParentNode): void {
  if (root instanceof HTMLElement) componentDisposers.get(root)?.();
  for (const element of root.querySelectorAll<HTMLElement>('.masked-value')) componentDisposers.get(element)?.();
}

async function clipboardDigest(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Only a digest is retained by the clear timer, never the copied plaintext. */
function scheduleClipboardClear(expectedDigest: string | undefined, generation: number, status: HTMLElement): void {
  clipboardClearTimer = window.setTimeout(() => {
    void (async () => {
      try {
        let currentDigest: string | undefined;
        try { if (navigator.clipboard.readText) currentDigest = await clipboardDigest(await navigator.clipboard.readText()); } catch { /* Clearing can be permitted when reading is unavailable. */ }
        if (generation === clipboardCopyGeneration && (currentDigest === undefined || expectedDigest === undefined || currentDigest === expectedDigest)) await navigator.clipboard.writeText('');
      } catch { status.textContent = 'Clipboard clearing was unavailable. Clear it when you are done.'; }
    })();
  }, 30_000);
}

/** Reveal is always an explicit confirmation followed by the shared passkey request. */
export function maskedValue(input: { route?: string; body?: unknown; label?: string } = {}): HTMLElement {
  const block = document.createElement('div'); block.className = 'masked-value';
  const output = document.createElement('span'); output.className = 'masked-value-output'; output.textContent = 'Hidden';
  const actions = document.createElement('div'); actions.className = 'value-actions';
  const status = document.createElement('span'); status.setAttribute('role', 'status');
  let value = '';
  let disposed = false;
  let revealGeneration = 0;
  let confirmation: AbortController | undefined;
  const hide = () => { ++revealGeneration; confirmation?.abort(); value = ''; output.textContent = 'Hidden'; status.textContent = 'Value hidden'; reveal.disabled = false; actions.replaceChildren(reveal); };
  const copy = button('Copy', () => {
    if (disposed) return;
    const copied = value;
    status.textContent = 'Copying.';
    void (async () => {
      try {
        await navigator.clipboard.writeText(copied);
        const generation = ++clipboardCopyGeneration;
        if (clipboardClearTimer !== undefined) window.clearTimeout(clipboardClearTimer);
        let digest: string | undefined;
        try { digest = await clipboardDigest(copied); } catch { /* Still attempt to clear if digest support becomes unavailable. */ }
        if (generation !== clipboardCopyGeneration) return;
        status.textContent = 'Copied. keysentry will try to clear the clipboard in 30 seconds.';
        scheduleClipboardClear(digest, generation, status);
      } catch { status.textContent = 'Copy was unavailable. Try again.'; }
    })();
  }, 'secondary');
  const reveal = button('Reveal', () => {
    if (disposed || reveal.disabled) return;
    const generation = ++revealGeneration;
    confirmation = new AbortController();
    reveal.disabled = true;
    void (async () => {
      try {
        if (!await confirmAction({ title: input.label ?? 'Reveal value', changes: ['keysentry will show this value in this browser until you hide it or leave the page.'], button: 'Reveal value', signal: confirmation?.signal })) return;
        if (disposed || generation !== revealGeneration) return;
        const result = await postWithPasskey<{ value: string }>(input.route ?? 'reveal', input.body ?? {});
        if (disposed || generation !== revealGeneration) { result.value = ''; return; }
        if (typeof result.value !== 'string') throw new Error();
        value = result.value; output.textContent = value; status.textContent = 'Value shown'; actions.replaceChildren(copy, button('Hide', hide, 'secondary'));
      } catch (error) {
        if (disposed || generation !== revealGeneration) return;
        // Team dashboard: other admins approve the reveal first; then Reveal again shows the value here.
        status.textContent = isTeamRequestRecorded(error) ? error.message : 'The value could not be revealed. Try again.';
      }
      finally { if (!disposed && generation === revealGeneration) reveal.disabled = false; }
    })();
  }, 'secondary');
  const pagehide = () => hide();
  window.addEventListener('pagehide', pagehide);
  componentDisposers.set(block, () => {
    if (disposed) return;
    hide(); disposed = true; actions.replaceChildren(); window.removeEventListener('pagehide', pagehide); componentDisposers.delete(block);
  });
  actions.append(reveal); block.append(output, actions, status); return block;
}
