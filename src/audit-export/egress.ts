import { X509Certificate } from 'node:crypto';
import { rulesForUserUrls, type SourcedEgressRule } from '../net/allowlist.js';
import { otlpLogsUrl } from './otlp.js';
import { s3RequestOrigin } from './s3.js';
import type { AuditExportTarget } from './types.js';

export const AUDIT_EXPORT_PURPOSE = 'audit export you configured';

/** Every HTTPS URL audit export contacts. Each authorizes only its own host (rulesForUserUrls). */
export function auditExportUrls(targets: readonly AuditExportTarget[]): string[] {
  const urls: string[] = [];
  for (const target of targets) {
    if (target.kind === 'otlp') urls.push(otlpLogsUrl(target.url));
    else if (target.kind === 'webhook') urls.push(target.url);
    else if (target.kind === 's3') urls.push(`${s3RequestOrigin(target)}/`);
  }
  return urls;
}

/** Egress rules for the HTTP targets; syslog goes through the TLS connector's own host:port allowance instead. */
export function auditExportEgressRules(targets: readonly AuditExportTarget[]): SourcedEgressRule[] {
  return rulesForUserUrls(auditExportUrls(targets), AUDIT_EXPORT_PURPOSE, 'config');
}

/** The exact host:port pairs the syslog connector may open. */
export function auditExportSyslogAllowance(targets: readonly AuditExportTarget[]): { host: string; port: number }[] {
  return targets.flatMap(target => target.kind === 'syslog' ? [{ host: target.host.toLowerCase(), port: target.port }] : []);
}

/**
 * Whether a configured HTTP(S) proxy covers a host. Syslog over TLS is not tunnelled, so such a host is refused
 * rather than contacted directly. NO_PROXY entries match exactly or as a dot-suffix; "*" disables the proxy.
 */
export function proxyAppliesTo(host: string, opts: { proxy?: string; noProxy?: readonly string[]; env?: NodeJS.ProcessEnv }): boolean {
  const env = opts.env ?? {};
  const proxy = opts.proxy ?? env.HTTPS_PROXY ?? env.https_proxy;
  if (!proxy?.trim()) return false;
  const name = host.toLowerCase().replace(/\.$/, '');
  const exclusions = [...opts.noProxy ?? [], ...`${env.NO_PROXY ?? env.no_proxy ?? ''}`.split(',')]
    .map(entry => entry.trim().toLowerCase().replace(/:\d+$/, '').replace(/^\*?\./, '.')).filter(Boolean);
  return !exclusions.some(entry => entry === '*' || entry === name || (entry.startsWith('.') ? name.endsWith(entry) : name.endsWith(`.${entry}`)));
}

/** Splits a PEM bundle into certificates; anything else in the file is refused. */
export function parseCaBundle(pem: string): string[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  const rest = pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim();
  if (!blocks.length || rest) throw new Error('network.caFile must contain only PEM certificates.');
  for (const block of blocks) {
    try { new X509Certificate(block); } catch { throw new Error('network.caFile contains a certificate that could not be read.'); }
  }
  return blocks;
}
