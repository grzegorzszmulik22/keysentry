import { button, notice } from '../components.js';

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, className?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
export const paragraph = (text: string): HTMLParagraphElement => el('p', text);
const errors = new WeakMap<HTMLElement, HTMLElement>();
let errorId = 0;
export function clearFieldError(control: HTMLElement): void {
  const error = errors.get(control); if (!error) return;
  const descriptions = (control.getAttribute('aria-describedby') ?? '').split(/\s+/).filter(id => id && id !== error.id);
  if (descriptions.length) control.setAttribute('aria-describedby', descriptions.join(' ')); else control.removeAttribute('aria-describedby');
  control.removeAttribute('aria-invalid'); error.remove(); errors.delete(control);
}
export function fieldError(control: HTMLElement, text: string): void {
  clearFieldError(control);
  const error = el('span', text, 'b-field-error'); error.id = `dashboard-field-error-${++errorId}`;
  control.setAttribute('aria-invalid', 'true');
  control.setAttribute('aria-describedby', [control.getAttribute('aria-describedby'), error.id].filter(Boolean).join(' '));
  control.insertAdjacentElement('afterend', error); errors.set(control, error);
}
export function field(label: string, control: HTMLElement): HTMLLabelElement {
  control.addEventListener('invalid', () => fieldError(control, 'Review this field.'));
  control.addEventListener('input', () => clearFieldError(control)); control.addEventListener('change', () => clearFieldError(control));
  const wrapper = el('label', undefined, 'b-field'); wrapper.append(el('span', label), control); return wrapper;
}
export function input(name: string, type: string, value?: string): HTMLInputElement {
  const control = el('input'); control.name = name; control.type = type;
  if (value !== undefined) control.value = value;
  return control;
}
export function actions(...nodes: Node[]): HTMLElement {
  const group = el('div', undefined, 'b-actions'); group.append(...nodes); return group;
}
export function status(): HTMLElement { const region = el('div', undefined, 'b-feedback'); region.setAttribute('role', 'status'); region.setAttribute('aria-live', 'polite'); return region; }
export function message(target: HTMLElement, title: string, text: string, kind: 'ok' | 'attention' | 'stop' | 'info' = 'info'): void {
  target.replaceChildren(notice(kind, title, text));
}
export function taskButton(label: string, feedback: HTMLElement, run: () => Promise<void>, disabled: boolean | (() => boolean) = false): HTMLButtonElement {
  const disabledNow = () => typeof disabled === 'function' ? disabled() : disabled;
  const control = button(label, () => {
    if (control.disabled || disabledNow()) return;
    control.disabled = true; control.setAttribute('aria-busy', 'true');
    void run().catch(() => { message(feedback, 'Request not completed', 'The request could not be completed. Try again.', 'attention'); })
      .finally(() => { control.disabled = disabledNow(); control.removeAttribute('aria-busy'); });
  });
  control.disabled = disabledNow(); return control;
}
export function scrollTable(content: HTMLTableElement): HTMLElement {
  const wrapper = el('div', undefined, 'table-scroll'); wrapper.tabIndex = 0; wrapper.setAttribute('role', 'region');
  wrapper.setAttribute('aria-label', content.caption?.textContent ?? 'Table'); wrapper.append(content); return wrapper;
}
export function section(title: string, ...nodes: Node[]): HTMLElement { const block = el('section', undefined, 'b-section'); block.append(el('h2', title), ...nodes); return block; }
export function list(items: string[]): HTMLUListElement { const block = el('ul'); for (const item of items) block.append(el('li', item)); return block; }
export function dateTime(value?: string | null): string {
  if (!value) return 'Not yet'; const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'Date unavailable';
}
export function numberInput(name: string, value: number, min: number, max?: number): HTMLInputElement {
  const control = input(name, 'number', String(value)); control.min = String(min); control.step = '1'; control.required = true;
  if (max !== undefined) control.max = String(max); return control;
}
export function validNumber(control: HTMLInputElement, min: number, max = Number.MAX_SAFE_INTEGER, integer = true): number | null {
  const number = control.valueAsNumber;
  return Number.isFinite(number) && number >= min && number <= max && (!integer || Number.isSafeInteger(number)) ? number : null;
}

interface PageLifetime { signal: AbortSignal; onDispose(callback: () => void): void; onMount(callback: () => void): void }
const lifetimes = new WeakMap<HTMLElement, PageLifetime & { dispose(): void }>();
/** The shell has no screen disposal hook; registration and DOM removal share this bounded lifetime. */
export function lifetime(root: HTMLElement): PageLifetime {
  const existing = lifetimes.get(root); if (existing) return existing;
  const controller = new AbortController(); const cleanup = new Set<() => void>(); const mounts = new Set<() => void>();
  let mounted = false;
  const initialHash = location.hash;
  const dispose = () => {
    if (controller.signal.aborted) return;
    controller.abort(); observer.disconnect();
    window.removeEventListener('pagehide', dispose); window.removeEventListener('hashchange', changed);
    for (const callback of cleanup) callback(); cleanup.clear(); mounts.clear();
  };
  const changed = () => { if (location.hash !== initialHash) dispose(); };
  const inspect = () => {
    if (controller.signal.aborted) return;
    if (root.isConnected && !mounted) { mounted = true; for (const callback of mounts) callback(); mounts.clear(); }
    else if (mounted && !root.isConnected) dispose();
  };
  const observer = new MutationObserver(inspect);
  observer.observe(document.documentElement, { childList: true, subtree: true });
  window.addEventListener('pagehide', dispose); window.addEventListener('hashchange', changed);
  const scope = {
    signal: controller.signal, dispose,
    onDispose(callback: () => void) { if (controller.signal.aborted) callback(); else cleanup.add(callback); },
    onMount(callback: () => void) { if (controller.signal.aborted) return; if (root.isConnected) { mounted = true; callback(); } else mounts.add(callback); },
  };
  lifetimes.set(root, scope); return scope;
}
export function disposeScreen(root: HTMLElement): void { lifetimes.get(root)?.dispose(); }

/** Download names are fixed by the screen, never interpolated from API data. */
export function download(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob); const link = el('a'); link.href = url; link.download = filename;
  document.body.append(link);
  try { link.click(); } finally { link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 0); }
}
