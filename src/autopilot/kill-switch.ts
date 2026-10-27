import type { AutopilotState } from './runner.js';

export interface SelfCheckResult { ok: boolean; reasons: string[] }

/** Disarming is deliberately local and never depends on an approval service. */
export function isAlertOnly(input: {
  env: NodeJS.ProcessEnv; state: AutopilotState; selfCheck: SelfCheckResult;
}): { alertOnly: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (input.env.KEYSENTRY_ALERT_ONLY === '1') reasons.push('Alert-only mode is enabled.');
  if (input.state.disarmed) reasons.push('Autopilot is disarmed.');
  if (!input.selfCheck.ok) reasons.push(...(input.selfCheck.reasons.length > 0
    ? input.selfCheck.reasons : ['The watcher self-check did not pass.']));
  return { alertOnly: reasons.length > 0, reasons };
}
