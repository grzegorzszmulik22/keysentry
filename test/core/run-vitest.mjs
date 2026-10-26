// Testing-only runner for environments that prohibit child processes. Production is unchanged.
// Vite normally spawns esbuild and a Windows `net use` capability probe before tests run.
import childProcess from 'node:child_process';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';

const originalExec = childProcess.exec;
childProcess.exec = function (command, ...args) {
  if (command === 'net use') {
    const callback = args.findLast((argument) => typeof argument === 'function');
    queueMicrotask(() => callback?.(null, '', ''));
    return new EventEmitter();
  }
  return originalExec.call(this, command, ...args);
};
syncBuiltinESMExports();

let context;
try {
  const { startVitest } = await import('vitest/node');
  const { default: ts } = await import('typescript');
  const args = process.argv.slice(2);
  const update = args.includes('-u') || args.includes('--update');
  const filters = args.filter((argument) => argument !== '-u' && argument !== '--update');
  context = await startVitest('test', filters.length ? filters : ['test/core'], {
    config: false,
    watch: false,
    update,
    pool: 'threads',
    poolOptions: { threads: { singleThread: true } },
  }, {
    esbuild: false,
    plugins: [{
      name: 'typescript-in-process',
      enforce: 'pre',
      transform(code, id) {
        if (/\.tsx?$/.test(id)) {
          return {
            code: ts.transpileModule(code, {
              compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2023 },
            }).outputText,
            map: null,
          };
        }
      },
    }],
  });
} finally {
  await context?.close();
  childProcess.exec = originalExec;
  syncBuiltinESMExports();
}
