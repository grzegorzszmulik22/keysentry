// The hosted control plane's process entry (Dockerfile.control-plane runs the bundle of this file on Cloud Run).
// Everything it does is in entry.ts so tests can run it with fakes; this file only binds it to the real process.
import { createFetchHttp } from '../../../src/http.js';
import { startHosted, stopOnSignals, type HostedLogEntry } from './entry.js';

/** One JSON line per event on stdout, which Cloud Logging stores as a structured entry. */
function log(entry: HostedLogEntry): void {
  process.stdout.write(`${JSON.stringify(entry)}\n`);
}

// An unexpected error never prints a stack trace or an upstream message: one fixed line, then exit.
process.on('uncaughtException', () => { log({ event: 'crashed', status: 1 }); process.exit(1); });
process.on('unhandledRejection', () => { log({ event: 'crashed', status: 1 }); process.exit(1); });

try {
  const running = await startHosted({ env: process.env, transport: createFetchHttp({ timeoutMs: 15_000, maxBytes: 8 * 1024 * 1024 }), log });
  stopOnSignals(process, running, code => {
    process.exitCode = code;
    // Normally nothing is left and Node exits now; a lingering keep-alive socket must not hold the instance.
    setTimeout(() => process.exit(code), 1_000).unref();
  });
} catch {
  // startHosted already logged which step failed.
  process.exitCode = 1;
}
