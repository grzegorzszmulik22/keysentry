export {
  MAX_WATCHER_CONFIG_BYTES, ensureWatcherStateDir, loadWatcherConfigFromEnv, parseWatcherConfig,
} from './config.js';
export type { WatcherConfig, WatcherConfigLoadOptions } from './config.js';
export { sealWatcherConfig, openWatcherConfig } from './seal.js';
export { detectPlatform, ownPlatformIncident } from './platform.js';
export type { DetectedPlatform } from './platform.js';
export { selfCheck, heartbeatDue, trackHttpClock } from './self-check.js';
export type { SelfCheckInput, SelfCheckResult } from './self-check.js';
export { createWatcherTick, runWatcherLoop, runOnce } from './loop.js';
export type {
  WatcherActionContext, WatcherTickDependencies, WatcherTickResult, WatcherTickState, RunOnceDependencies,
} from './loop.js';
export { RESUME_PREFIX, signWatcherResume, verifyWatcherResume, createActionsRecovery, createSequencedStateRecord } from './recovery.js';
export type {
  SignedWatcherResume, RecoveryDeviceKey, WatcherResumeVerification, ActionsRecoveryState, ActionsRecoveryOptions,
  ActionsRecovery, SequencedStateRecord, SequencedStatePersistence,
} from './recovery.js';
export { createWatcherResumeRelay } from './resume-relay.js';
export type { WatcherResumeRelayOptions, WatcherResumeRelayPollResult, WatcherResumeRelay } from './resume-relay.js';
