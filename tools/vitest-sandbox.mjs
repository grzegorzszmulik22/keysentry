// Run vitest in process, without an esbuild child process (for sandboxed environments). usage: node tools/vitest-sandbox.mjs test/<module>
import { startVitest } from 'vitest/node';
import ts from 'typescript';

const context = await startVitest('test', process.argv.slice(2), {
  config: false,
  watch: false,
  testTimeout: 20_000,
  pool: 'threads',
  poolOptions: { threads: { singleThread: true } },
}, {
  resolve: { preserveSymlinks: true },
  esbuild: false,
  plugins: [{
    name: 'typescript-in-process',
    enforce: 'pre',
    transform(code, id) {
      if (!/\/(?:src|test)\/.*\.ts$/.test(id.replaceAll('\\', '/'))) return;
      return {
        code: ts.transpileModule(code, {
          compilerOptions: { target: ts.ScriptTarget.ES2023, module: ts.ModuleKind.ESNext, sourceMap: true },
        }).outputText,
        map: null,
      };
    },
  }],
});
await context?.close();
