export {
  ARMED_PLAN_PREFIX, adoptionNeeded, autopilotEligibility, buildArmedPlan, signArmedPlan, verifyArmedPlan,
} from './armed-plan.js';
export { checkScope } from './scope.js';
export {
  DEFAULT_SOURCES, HIGH_CONFIDENCE_TITLE, PLATFORM_HOSTS, SECURITY_PHRASE, SECURITY_TITLE, classifyItem,
  isSecurityAdvisory, mentionsHost,
} from './sources.js';
export { updateIncidents } from './incidents.js';
export { isAlertOnly } from './kill-switch.js';
export type { SelfCheckResult } from './kill-switch.js';
export { runAutopilot, resumeWaves, settleWaves } from './runner.js';
export type { AutopilotState, AutopilotWave, AutopilotDeps, AutopilotInput, WaveRecoveryDeps, WaveRecoveryInput, WaveRecoveryResult } from './runner.js';
