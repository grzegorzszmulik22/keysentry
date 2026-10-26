// Sandbox fallback: avoid esbuild's child process without changing the shared Vitest configuration.
import { startVitest } from 'vitest/node';
import ts from 'typescript';

const context = await startVitest('test', ['test/hosts'], {
  config: false,
  watch: false,
  testTimeout: 20_000,
  pool: 'threads',
  poolOptions: { threads: { singleThread: true } },
}, {
  resolve: { preserveSymlinks: true },
  esbuild: false,
  plugins: [{
    name: 'hosts-typescript-in-process',
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
