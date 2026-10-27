export { CborError, decodeCbor } from './cbor.js';
export { coseToPublicKey } from './cose.js';
export { parseAuthData } from './authdata.js';
export type { AuthData } from './authdata.js';
export { WebAuthnError, verifyRegistration, verifyAssertion } from './verify.js';
export type { RegistrationInput, AssertionInput } from './verify.js';
