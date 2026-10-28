/**
 * Provider credentials that name a resource instead of granting access. They are stored next to their secret, but
 * they are never registered with the redactor: masking a Google project number would also mask it inside the key
 * references (projects/<number>/locations/global/keys/<id>) that later revocation reads back from the journal.
 */
export const NON_SECRET_CREDENTIALS: readonly string[] = Object.freeze(['GOOGLE_API_KEYS_PROJECT']);

/** Credential values to register as secrets: every present value except NON_SECRET_CREDENTIALS. */
export function secretCredentialValues(credentials: Readonly<Record<string, string | undefined>>): string[] {
  return Object.entries(credentials).filter(([name, value]) => value !== undefined && !NON_SECRET_CREDENTIALS.includes(name))
    .map(([, value]) => value!);
}
