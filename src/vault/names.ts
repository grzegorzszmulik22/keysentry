export function validateVaultName(name: string): void {
  if (typeof name !== 'string' || !/^[A-Za-z0-9/_.@#-]{1,200}$/.test(name)) {
    throw new TypeError('Vault names must contain 1 to 200 letters, digits, /, _, ., @, # or -.');
  }
}
