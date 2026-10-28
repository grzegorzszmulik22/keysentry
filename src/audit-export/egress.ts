import { rulesForUserUrls, type SourcedEgressRule } from '../net/allowlist.js';
import { parseCaBundle as parseTransportCaBundle, usesProxy } from '../net/transport.js';
import { otlpLogsUrl } from './otlp.js';
import { s3RequestOrigin } from './s3.js';
import type { AuditExportTarget } from './types.js';

export const AUDIT_EXPORT_PURPOSE = 'audit export you configured';

/** RFC 5425: syslog over TLS uses port 6514. */
const SYSLOG_TLS_PORT = 6514;

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
 * Whether the configured proxy covers a syslog host. Syslog over TLS is not tunnelled, so such a host is refused rather
 * than contacted directly. The decision is the HTTPS transport's own (src/net/transport.ts usesProxy, review L1): the
 * same proxy selection (network.proxy, then a non-empty HTTPS_PROXY or https_proxy), the same no-proxy list and the same
 * matching (a bare entry is one exact host; `.example.com` covers subdomains; `*` covers everything). A team policy that
 * requires the proxy covers every host.
 */
export function proxyAppliesTo(host: string, opts: {
  proxy?: string; noProxy?: readonly string[]; env?: NodeJS.ProcessEnv; port?: number; requireProxy?: boolean;
}): boolean {
  return usesProxy(host, opts.port ?? SYSLOG_TLS_PORT, {
    ...(opts.proxy ? { configProxy: opts.proxy } : {}), ...(opts.noProxy ? { configNoProxy: opts.noProxy } : {}),
    env: opts.env ?? {}, ...(opts.requireProxy ? { requireProxy: true } : {}),
  });
}

/**
 * Splits a PEM bundle into certificates with the transport's parser (review L1), so a bundle that works for HTTPS
 * (including `#` comment lines) works for syslog, and anything else in the file is refused the same way.
 */
export function parseCaBundle(pem: string): string[] {
  return parseTransportCaBundle(pem).pems;
}
