export class VaultUnavailableError extends Error {
  readonly code = 'VAULT_UNAVAILABLE';
  constructor(message = 'The credential store is unavailable. Choose the encrypted file to continue.') {
    super(message);
    this.name = 'VaultUnavailableError';
  }
}

export class VaultLockedError extends Error {
  readonly code = 'VAULT_LOCKED';
  constructor(message = 'The encrypted vault could not be opened. Check your passphrase and the vault file.') {
    super(message);
    this.name = 'VaultLockedError';
  }
}

export class VaultReadOnlyError extends Error {
  readonly code = 'VAULT_READ_ONLY';
  constructor(message = 'The environment vault is read-only. Set the corresponding environment variable instead.') {
    super(message);
    this.name = 'VaultReadOnlyError';
  }
}
