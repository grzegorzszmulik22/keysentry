// Inside the cloud box: attestation tokens from the launcher, the relay session, sealing at rest and the watcher.
export { BoxAgentError, boxAttestationAudience, startBoxAgent } from './agent.js';
export type { BoxAgent, BoxAgentDependencies, BoxAgentState, BoxAgentStatus } from './agent.js';
export { BOX_STATE_DIR, METADATA_ATTRIBUTES, readBoxRoute, readMetadataAttribute, relayCredential, startProductionBoxAgent } from './main.js';
export type { BoxRouteMetadata, ProductionBoxOptions } from './main.js';
export { createNoticeSender } from './notice.js';
export {
  BOX_DEPLOYMENT_VARIABLES, BoxPayloadError, decodeBoxPayload, encodeBoxPayload, isBoxId, isEd25519Spki,
} from './payload.js';
export type { BoxDeploymentVariable, BoxEnrollPayload, BoxNoticeKit, BoxNoticeRecord, BoxPayload, BoxSettings, BoxUnlockPayload } from './payload.js';
export { BoxRelayError, createHttpBoxRelay } from './relay.js';
export type { BoxRelay } from './relay.js';
export {
  DEFAULT_TOKEN_PATH, TEESERVER_SOCKET, TEE_TOKEN_MAX_BYTES, TEE_TOKEN_MIN_INTERVAL_MS, TEE_TOKEN_TIMEOUT_MS, TeeTokenError, createTeeTokenSource,
} from './tee.js';
export type { TeeTokenRequest, TeeTokenSource, TeeTokenSourceOptions } from './tee.js';
