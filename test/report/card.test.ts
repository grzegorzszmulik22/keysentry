import { describe, expect, it } from 'vitest';
import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { renderCard } from '../../src/report/card.js';

const optOut = { platform: false, counts: false };
const parse = (svg: string) => new XMLParser({ ignoreAttributes: false, parseTagValue: false }).parse(svg).svg;

describe('readiness card', () => {
  it('contains no names, hints, platform or counts unless opted in', () => {
    const input = {
      score: 92,
      rotated: { keys: 14, seconds: 220, platform: 'Railway' },
      optIn: optOut,
      projectName: 'private-customer',
      keyName: 'OPENAI_API_KEY',
      hint: 'sk-proj…ABCD',
      value: 'planted-private-value',
    };
    const svg = renderCard(input);
    for (const privateText of ['private-customer', 'OPENAI_API_KEY', 'sk-proj', 'planted-private-value', 'Railway', 'rotated', '14 keys', '3 min']) {
      expect(svg).not.toContain(privateText);
    }
    expect(parse(svg).text.map((item: Record<string, string>) => item['#text'])).toContain('keysentry');
    expect(parse(svg).title['#text']).toContain('92/100');
    expect(parse(svg).desc['#text']).toContain('92/100');
  });

  it('shares platform and rotation counts only through their independent opt-ins', () => {
    const rotated = { keys: 14, seconds: 220, platform: 'railway' };
    const counts = renderCard({ score: 92, rotated, optIn: { platform: false, counts: true } });
    expect(counts).toContain('rotated 14 keys in 3 min 40 s');
    expect(counts).not.toContain('Railway');
    const platform = renderCard({ score: 92, rotated, optIn: { platform: true, counts: false } });
    expect(platform).toContain('after the Railway incident');
    expect(platform).not.toContain('rotated');
    const both = renderCard({ score: 92, rotated, optIn: { platform: true, counts: true } });
    expect(both).toContain('rotated 14 keys in 3 min 40 s');
    expect(both).toContain('after the Railway incident');
    expect(parse(both).title['#text']).not.toContain('Railway');
    expect(parse(both).desc['#text']).not.toContain('Railway');
  });

  it('is self-contained valid SVG with fixed elements and attributes', () => {
    const svg = renderCard({ score: 92, rotated: { keys: 14, seconds: 220, platform: 'Railway' }, optIn: { platform: true, counts: true } });
    expect(XMLValidator.validate(svg)).toBe(true);
    const root = parse(svg);
    expect(root['@_width']).toBe('1200');
    expect(root['@_height']).toBe('630');
    expect(root['@_viewBox']).toBe('0 0 1200 630');
    expect(root['@_role']).toBe('img');
    expect(root.title).toBeTruthy();
    expect(root.desc).toBeTruthy();
    const allowedTags = new Set(['svg', 'title', 'desc', 'rect', 'circle', 'path', 'text', 'tspan', 'g', 'defs', 'linearGradient', 'stop']);
    const allowedAttributes = new Set(['xmlns', 'width', 'height', 'viewBox', 'role', 'aria-labelledby', 'id', 'x', 'y', 'rx', 'ry', 'cx', 'cy', 'r', 'fill', 'stroke', 'stroke-width', 'stroke-dasharray', 'stroke-dashoffset', 'stroke-linecap', 'pathLength', 'transform', 'd', 'font-family', 'font-size', 'font-weight', 'text-anchor']);
    function visit(nodes: Record<string, unknown>[]) {
      for (const node of nodes) {
        for (const [key, value] of Object.entries(node)) {
          if (key === ':@') {
            for (const [name, attribute] of Object.entries(value as Record<string, unknown>)) {
              expect(allowedAttributes.has(name.slice(2)), name).toBe(true);
              expect(String(attribute)).not.toMatch(/url\s*\(|javascript:|data:|https?:\/\//i);
            }
          } else if (key !== '#text') {
            expect(allowedTags.has(key), key).toBe(true);
            visit(value as Record<string, unknown>[]);
          }
        }
      }
    }
    // The SVG namespace identifies the format, rather than loading a resource.
    const tree = new XMLParser({ ignoreAttributes: false, preserveOrder: true }).parse(svg);
    delete tree[0][':@']['@_xmlns'];
    visit(tree);
    expect(svg).toContain('system-ui');
    expect(svg).not.toMatch(/<script|foreignObject|\bon[a-z]+=|\bhref=|<style|<image/i);
  });

  it('draws the score as a large number with a proportional ring and the key-tag motif', () => {
    const root = parse(renderCard({ score: 92, optIn: optOut }));
    const circles = Array.isArray(root.circle) ? root.circle : [root.circle];
    const ring = circles.find((circle: Record<string, string>) => circle['@_pathLength'] === '100');
    expect(ring['@_stroke-dashoffset']).toBe('8');
    const text = Array.isArray(root.text) ? root.text : [root.text];
    expect(text.some((item: Record<string, string>) => item['#text'] === '92' && Number(item['@_font-size']) >= 100)).toBe(true);
    // A small brass circle sits inside the rounded tag at the brand's left edge.
    expect(circles.some((circle: Record<string, string>) => circle['@_stroke'] === '#8A5E0C' && Number(circle['@_r']) < 20)).toBe(true);
    expect(root.rect).toBeTruthy();
  });

  it.each([
    { score: 92.6, keys: 14.9, seconds: 220.9, wantScore: '93/100', wantCounts: 'rotated 14 keys in 3 min 40 s' },
    { score: -10, keys: -1, seconds: -12, wantScore: '0/100', wantCounts: 'rotated 0 keys in 0 min 0 s' },
    { score: 500, keys: 1, seconds: 60, wantScore: '100/100', wantCounts: 'rotated 1 keys in 1 min 0 s' },
    { score: Number.NaN, keys: Number.POSITIVE_INFINITY, seconds: Number.NEGATIVE_INFINITY, wantScore: '0/100', wantCounts: 'rotated 0 keys in 0 min 0 s' },
  ])('formats and bounds numeric input: $wantScore', ({ score, keys, seconds, wantScore, wantCounts }) => {
    const svg = renderCard({ score, rotated: { keys, seconds }, optIn: { platform: false, counts: true } });
    expect(parse(svg).title['#text']).toContain(wantScore);
    expect(svg).toContain(wantCounts);
    expect(svg).not.toMatch(/NaN|Infinity/);
  });

  it('does not reflect injected attributes or secret-shaped platform strings', () => {
    const planted = 'sk-proj-planted-value-0123456789ABCDEF';
    for (const platform of ['<script>alert(1)</script>', 'Railway" onload="alert(1)', 'Railway & <Private>', planted]) {
      const svg = renderCard({ score: 92, rotated: { keys: 2, seconds: 1, platform }, optIn: { platform: true, counts: true } });
      expect(XMLValidator.validate(svg)).toBe(true);
      expect(svg).not.toContain(platform);
      expect(svg).not.toContain('after the');
      expect(svg).not.toMatch(/script|onload|alert\(1\)/);
    }
    const raw = '92" onload="alert(1)';
    const svg = renderCard({ score: raw as unknown as number, optIn: optOut });
    expect(parse(svg).title['#text']).toContain('0/100');
    expect(svg).not.toContain(raw);
  });

  it('omits unavailable rotation details even when sharing is enabled', () => {
    const svg = renderCard({ score: 92, optIn: { platform: true, counts: true } });
    expect(svg).not.toContain('rotated');
    expect(svg).not.toContain('after the');
  });
});
