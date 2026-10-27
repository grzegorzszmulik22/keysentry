import { post, type DashboardSession } from '../api.js';
import { actions, download, el, field, input, lifetime, message, paragraph, status, taskButton } from './components-b.js';

interface Card { svg: string; score: number }

async function pngFromImage(image: HTMLImageElement, signal: AbortSignal): Promise<Blob> {
  if (signal.aborted) throw new Error();
  await image.decode();
  if (signal.aborted) throw new Error();
  const canvas = document.createElement('canvas'); canvas.width = 1200; canvas.height = 630;
  const context = canvas.getContext('2d'); if (!context) throw new Error();
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  return new Promise<Blob>((resolve, reject) => {
    canvas.toBlob(blob => { if (blob && !signal.aborted) resolve(blob); else reject(new Error()); }, 'image/png');
  });
}

/** SVG is decoded as an image, never inserted into the page's document. */
export async function renderCard(_session: DashboardSession): Promise<HTMLElement> {
  const root = el('div', undefined, 'screen-b'); const life = lifetime(root); const feedback = status();
  const platform = input('platform', 'checkbox'); const counts = input('counts', 'checkbox');
  const preview = el('img', undefined, 'b-readiness-card'); preview.width = 1200; preview.height = 630; preview.alt = 'Readiness card preview';
  const score = paragraph('Preparing the readiness card.');
  let generation = 0; let current: Blob | undefined; let objectUrl: string | undefined; let busy = false;
  life.onDispose(() => { generation++; current = undefined; if (objectUrl) URL.revokeObjectURL(objectUrl); objectUrl = undefined; preview.removeAttribute('src'); });
  const update = async () => {
    const request = ++generation; busy = true; copy.disabled = true; save.disabled = true;
    try {
      const card = await post<Card>('card', { platform: platform.checked, counts: counts.checked });
      if (life.signal.aborted || request !== generation) return;
      const blob = new Blob([card.svg], { type: 'image/svg+xml' }); const nextUrl = URL.createObjectURL(blob);
      const previous = objectUrl; objectUrl = nextUrl; current = blob; preview.src = nextUrl;
      if (previous) URL.revokeObjectURL(previous);
      score.textContent = `Readiness ${card.score}/100.`; feedback.replaceChildren();
    } catch {
      if (!life.signal.aborted && request === generation) {
        current = undefined; if (objectUrl) URL.revokeObjectURL(objectUrl); objectUrl = undefined; preview.removeAttribute('src');
        message(feedback, 'Card unavailable', 'The readiness card could not be prepared. Change an option to try again.', 'attention');
      }
    } finally {
      if (!life.signal.aborted && request === generation) { busy = false; copy.disabled = !current; save.disabled = !current; }
    }
  };
  preview.addEventListener('error', () => { if (!life.signal.aborted && current) message(feedback, 'Preview unavailable', 'This browser could not display the card. You can still choose Download SVG.', 'attention'); });
  const save = taskButton('Download SVG', feedback, async () => { if (current && !busy && !life.signal.aborted) download(current, 'keysentry-readiness.svg'); });
  const copy = taskButton('Copy image', feedback, async () => {
    if (!current || busy || life.signal.aborted) return;
    if (!navigator.clipboard?.write || typeof ClipboardItem === 'undefined' || typeof preview.decode !== 'function') {
      message(feedback, 'Copy image unavailable', 'This browser cannot copy an image here. Choose Download SVG to save the card.'); return;
    }
    let png: Promise<Blob> | undefined;
    try {
      const version = generation; const snapshot = new Image(); snapshot.src = preview.src;
      png = pngFromImage(snapshot, life.signal);
      const item = new ClipboardItem({ 'image/png': png });
      await navigator.clipboard.write([item]);
      if (!life.signal.aborted && version === generation) message(feedback, 'Image copied', 'The readiness card was copied as a PNG image.', 'ok');
    } catch {
      if (png) await png.catch(() => {});
      if (!life.signal.aborted) message(feedback, 'Copy image unavailable', 'The image could not be copied. Choose Download SVG to save the card.');
    }
  });
  platform.addEventListener('change', () => { void update(); }); counts.addEventListener('change', () => { void update(); });
  root.append(paragraph('The card shares your readiness score. Platform names and rotation counts are included only when you choose them below.'),
    field('Include platform names', platform), field('Include rotation counts', counts), score, preview, actions(save, copy), feedback);
  await update(); return root;
}
