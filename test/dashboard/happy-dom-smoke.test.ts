// @vitest-environment happy-dom
import { expect, test } from 'vitest';
test('dom', () => { document.body.innerHTML = '<p id="x">hi</p>'; expect(document.getElementById('x')?.textContent).toBe('hi'); });
