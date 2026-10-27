import { expect, it } from 'vitest';
import { scanHistory } from '../../src/firstrun/scan-history.js';

it('streams fifty thousand synthetic commits within the time budget', async () => {
  let lines = 0;
  let bytes = 0;
  const started = performance.now();
  const result = await scanHistory('/synthetic-project', { maxCommits: 50_000, git: async (_args, { onLine, signal }) => {
    const emit = (line: string) => { lines++; bytes += Buffer.byteLength(line) + 1; onLine(line); };
    for (let index = 0; index < 50_000 && !signal.aborted; index++) {
      emit(`\x00${index.toString(16).padStart(40, '0')}\x002026-10-27T12:00:00Z`);
      emit('diff --git a/application.ts b/application.ts');
      emit('+++ b/application.ts');
      emit('@@ -0,0 +1 @@');
      emit('+PORT=3000');
    }
    return { code: 0 };
  } });
  const elapsedMs = performance.now() - started;
  expect(result).toMatchObject({ commits: 50_000, complete: true, hits: [] });
  expect(elapsedMs).toBeLessThan(5000);
  console.info(JSON.stringify({ benchmark: 'first-run synthetic history', commits: result.commits, lines, bytes, elapsedMs: Math.round(elapsedMs) }));
});
