import { createBoxSealer, type BoxSealOptions, type BoxSealer } from './standard.js';

/** Customer settings use precisely the same envelope/KMS flow, with their audience and key name. */
export function createByoKmsSealer(options: Omit<BoxSealOptions, 'config'> & {
  config: Omit<BoxSealOptions['config'], 'mode'> & { mode?: 'byo-kms' };
}): BoxSealer {
  return createBoxSealer({ ...options, config: { ...options.config, mode: 'byo-kms' } });
}
