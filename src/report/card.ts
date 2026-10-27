export interface ReadinessCardInput {
  score: number;
  rotated?: { keys: number; seconds: number; platform?: string };
  optIn: { platform: boolean; counts: boolean };
}

type Element = 'svg' | 'title' | 'desc' | 'rect' | 'circle' | 'text';
type Attribute =
  | 'xmlns' | 'width' | 'height' | 'viewBox' | 'role' | 'aria-labelledby' | 'id'
  | 'x' | 'y' | 'rx' | 'cx' | 'cy' | 'r' | 'fill' | 'stroke' | 'stroke-width'
  | 'stroke-dasharray' | 'stroke-dashoffset' | 'stroke-linecap' | 'pathLength'
  | 'transform' | 'font-family' | 'font-size' | 'font-weight' | 'text-anchor';

const colors = { bg: '#F3F6F8', surface: '#FFFFFF', ink: '#1B2533', muted: '#566170', line: '#D3DAE1', brass: '#8A5E0C' };
const font = 'system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", sans-serif';
const platforms = new Map([
  ['railway', 'Railway'], ['vercel', 'Vercel'], ['render', 'Render'],
  ['fly', 'Fly.io'], ['fly.io', 'Fly.io'],
  ['github-actions', 'GitHub Actions'], ['github actions', 'GitHub Actions'],
]);

function escapeXml(text: string): string {
  return text.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[character]!);
}

// Tags and attribute names are fixed by the renderer; all text and attribute values are escaped.
function element(tag: Element, attributes: Partial<Record<Attribute, string>>, content = ''): string {
  const attrs = Object.entries(attributes).map(([name, value]) => ` ${name}="${escapeXml(value)}"`).join('');
  return `<${tag}${attrs}>${content}</${tag}>`;
}

function integer(value: number, maximum = Number.MAX_SAFE_INTEGER): number {
  return typeof value === 'number' && Number.isFinite(value) ? Math.floor(Math.max(0, Math.min(maximum, value))) : 0;
}

function number(value: number): string {
  return value.toFixed(0);
}

function text(content: string, x: number, y: number, size: number, attributes: Partial<Record<Attribute, string>> = {}): string {
  return element('text', { x: number(x), y: number(y), 'font-family': font, 'font-size': number(size), fill: colors.ink, ...attributes }, escapeXml(content));
}

/** A value-free share card. Only supported platform labels and explicitly shared counts can appear. */
export function renderCard(input: ReadinessCardInput): string {
  const score = integer(typeof input.score === 'number' ? Math.round(input.score) : 0, 100);
  const scoreText = `${number(score)}/100`;
  let counts: string | undefined;
  if (input.optIn.counts && input.rotated) {
    const seconds = integer(input.rotated.seconds);
    counts = `rotated ${number(integer(input.rotated.keys))} keys in ${number(Math.floor(seconds / 60))} min ${number(seconds % 60)} s`;
  }
  // Never use arbitrary supplied text as a platform label: it may contain a value or a project name.
  const platform = input.optIn.platform && typeof input.rotated?.platform === 'string'
    ? platforms.get(input.rotated.platform.trim().toLowerCase()) : undefined;
  const children = [
    element('title', { id: 'keysentry-card-title' }, escapeXml(`keysentry ${scoreText}`)),
    element('desc', { id: 'keysentry-card-desc' }, escapeXml(counts ? `${scoreText}; ${counts}.` : `${scoreText}.`)),
    element('rect', { x: '0', y: '0', width: '1200', height: '630', fill: colors.bg }),
    element('circle', { cx: '315', cy: '315', r: '168', fill: 'none', stroke: colors.line, 'stroke-width': '16' }),
    element('circle', { cx: '315', cy: '315', r: '168', fill: 'none', stroke: colors.brass, 'stroke-width': '16', pathLength: '100', 'stroke-dasharray': '100', 'stroke-dashoffset': number(100 - score), 'stroke-linecap': 'butt', transform: 'rotate(-90 315 315)' }),
    text(number(score), 315, 337, 152, { 'text-anchor': 'middle', 'font-weight': '650' }),
    text('/100', 315, 393, 31, { 'text-anchor': 'middle', fill: colors.muted }),
  ];
  // The shared achievement is the headline when the user opted in; otherwise the brand tag carries the right side.
  children.push(text('Breach readiness', 600, 150, 31, { fill: colors.muted }));
  if (counts) {
    const [verb, rest] = [counts.slice(0, counts.indexOf(' in ')), counts.slice(counts.indexOf(' in ') + 1)];
    const headline = verb.charAt(0).toUpperCase() + verb.slice(1);
    children.push(text(headline, 600, 262, Math.min(61, Math.floor(560 / (headline.length * 0.56))), { 'font-weight': '650' }));
    children.push(text(rest, 600, 336, Math.min(61, Math.floor(560 / (rest.length * 0.56))), { 'font-weight': '650' }));
    if (platform) children.push(text(`after the ${platform} incident`, 600, 396, 31, { fill: colors.muted }));
  } else if (platform) {
    // Platform shared without counts: say that keys were replaced, never how many.
    children.push(text('Keys replaced', 600, 262, 61, { 'font-weight': '650' }));
    children.push(text(`after the ${platform} incident`, 600, 322, 31, { fill: colors.muted }));
  }
  const tagY = counts || platform ? 460 : 252;
  children.push(
    element('rect', { x: '600', y: number(tagY), width: '320', height: '84', rx: '10', fill: colors.surface, stroke: colors.line, 'stroke-width': '1' }),
    element('circle', { cx: '634', cy: number(tagY + 42), r: '10', fill: colors.bg, stroke: colors.brass, 'stroke-width': '4' }),
    text('keysentry', 664, tagY + 55, 39, { 'font-weight': '650' }),
  );
  return element('svg', { xmlns: 'http://www.w3.org/2000/svg', width: '1200', height: '630', viewBox: '0 0 1200 630', role: 'img', 'aria-labelledby': 'keysentry-card-title keysentry-card-desc' }, children.join('\n'));
}
