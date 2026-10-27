import { createHash, X509Certificate, type KeyObject } from 'node:crypto';

/** SHA-256 of Google's recorded Confidential Space Root CA DER (§1b of phase4-facts). */
export const CONFIDENTIAL_SPACE_ROOT_SHA256 = '148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39';

function certificate(value: unknown): X509Certificate {
  if (typeof value !== 'string' || value.length === 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('The certificate encoding is not valid.');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) throw new Error('The certificate encoding is not valid.');
  const parsed = new X509Certificate(bytes);
  if (!parsed.raw.equals(bytes)) throw new Error('The certificate encoding is not valid.');
  return parsed;
}

/** Validate the complete offline PKI path; the returned leaf key still needs to verify the JWT. */
export function verifyCertificateChain(x5c: unknown, now: Date, root?: X509Certificate): KeyObject {
  try {
    if (!Array.isArray(x5c) || x5c.length !== 3) {
      throw new Error('The certificate chain must contain three certificates.');
    }
    const leaf = certificate(x5c[0]);
    const intermediate = certificate(x5c[1]);
    const chainRoot = certificate(x5c[2]);
    const time = now.getTime();
    if (!Number.isFinite(time) || [leaf, intermediate, chainRoot].some(cert => {
      const validFrom = Date.parse(cert.validFrom);
      const validTo = Date.parse(cert.validTo);
      return !Number.isFinite(validFrom) || !Number.isFinite(validTo) || time < validFrom || time > validTo;
    })) {
      throw new Error('A certificate is outside its validity period.');
    }
    const pinnedHash = root ? createHash('sha256').update(root.raw).digest('hex') : CONFIDENTIAL_SPACE_ROOT_SHA256;
    if (createHash('sha256').update(chainRoot.raw).digest('hex') !== pinnedHash) {
      throw new Error('The certificate root does not match the pinned root.');
    }
    if (!intermediate.ca || !chainRoot.ca
      || !leaf.checkIssued(intermediate) || !leaf.verify(intermediate.publicKey)
      || !intermediate.checkIssued(chainRoot) || !intermediate.verify(chainRoot.publicKey)
      || !chainRoot.checkIssued(chainRoot) || !chainRoot.verify(chainRoot.publicKey)) {
      throw new Error('The certificate chain could not be verified.');
    }
    const key = leaf.publicKey;
    if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
      || key.asymmetricKeyDetails?.publicExponent !== 65537n) {
      throw new Error('The certificate signing key must be RSA with at least 2048 bits and exponent 65537.');
    }
    return key;
  } catch {
    // OpenSSL's parsing diagnostics may include untrusted certificate text.
    throw new Error('The attestation certificate chain could not be verified.');
  }
}
