import { RotationAbortedError } from '../types.js';
import type { RotationReport } from '../types.js';

/** Only locally constructed diagnostics may cross the CLI error boundary. */
export class CliError extends Error {}

/** Cancellation still exits unsuccessfully, after delivery of existing results. */
export class RotationInterruptedError extends RotationAbortedError {
  constructor(readonly report: RotationReport) {
    super('Rotation interrupted by the operator.');
  }
}
