// Offline fallback for Windows sandboxes that block esbuild's child process.
// Usage: node test/providers/run-vitest.mjs [test file filters...]
import ts from 'typescript';
import { startVitest } from 'vitest/node';

const filters = process.argv.slice(2);
const runner = await startVitest('test', filters.length ? filters : ['test/providers'], {
  config: false,
  watch: false,
  pool: 'threads',
  minWorkers: 1,
  maxWorkers: 1,
  fileParallelism: false,
  include: ['test/providers/**/*.test.ts'],
}, {
  esbuild: false,
  resolve: { preserveSymlinks: true },
  plugins: [{
    name: 'providers-offline-typescript',
    enforce: 'pre',
    transform(source, id) {
      const fileName = id.split('?')[0];
      if (!fileName?.endsWith('.ts')) return;
      const result = ts.transpileModule(source, {
        fileName,
        compilerOptions: {
          target: ts.ScriptTarget.ES2023,
          module: ts.ModuleKind.ESNext,
          sourceMap: true,
          inlineSources: true,
          esModuleInterop: true,
        },
      });
      return { code: result.outputText, map: result.sourceMapText };
    },
  }],
});
if (!runner) process.exitCode = 1;
await runner?.close();
