import { offlineNotice } from '../feeds/offline.js';
import { PROXY_AUTH_CREDENTIAL, type NetworkSummary } from '../net/transport.js';
import type { DoctorItem } from './doctor.js';

const MAX_LISTED_CERTIFICATES = 50;

/** Proxy, extra certificate authorities and offline mode. Input is already secret-free (summarizeNetwork). */
export function networkDoctorItems(summary: NetworkSummary, now: Date = new Date()): DoctorItem[] {
  const items: DoctorItem[] = [];
  if (summary.proxy) {
    const from = summary.proxy.source === 'config' ? 'network.proxy in keysentry.yaml' : 'HTTPS_PROXY';
    const credentials = summary.proxy.credentials === 'env' ? 'Proxy credentials come from HTTPS_PROXY.'
      : summary.proxy.credentials === 'vault' ? `Proxy credentials come from the vault (${PROXY_AUTH_CREDENTIAL}).`
        : 'No proxy credentials are configured.';
    const direct = summary.noProxy.length ? ` Direct, without the proxy: ${summary.noProxy.join(', ')}.` : '';
    items.push({
      area: 'network', status: 'ok', title: 'Proxy',
      detail: `Requests go through ${summary.proxy.origin} (from ${from}). ${credentials}${direct} The allow-list still applies to each destination host, not to the proxy.`,
    });
    if (summary.proxy.credentials !== 'none' && summary.proxy.origin.startsWith('http://')) {
      items.push({
        area: 'network', status: 'warn', title: 'Proxy credentials',
        detail: 'The proxy is reached over http://, so its credentials cross the local network unencrypted. Destination traffic stays encrypted inside the tunnel.',
        fix: 'Use an https:// proxy address if your proxy supports it.',
      });
    }
  } else if (summary.requireProxy) {
    items.push({
      area: 'network', status: 'fail', title: 'Proxy',
      detail: 'The signed team policy requires a proxy, but none is configured, so keysentry refuses outbound requests.',
      fix: 'Set network.proxy in keysentry.yaml or HTTPS_PROXY.',
    });
  } else {
    items.push({ area: 'network', status: 'info', title: 'Proxy', detail: 'No proxy is configured; keysentry connects to each allowed host directly.' });
  }
  if (summary.noProxyIgnored.length) {
    items.push({
      area: 'network', status: 'warn', title: 'No-proxy entries ignored',
      detail: `${summary.noProxyIgnored.length} no-proxy ${summary.noProxyIgnored.length === 1 ? 'entry is' : 'entries are'} not supported and still use the proxy: ${summary.noProxyIgnored.join(', ')}. Use exact hosts or .suffix entries; address ranges are not supported.`,
    });
  }

  if (summary.ca && 'error' in summary.ca) {
    items.push({
      area: 'network', status: 'fail', title: 'Extra certificate authorities',
      detail: `${summary.ca.error} Until it is fixed, keysentry refuses outbound requests rather than ignoring the file.`,
      fix: 'Check network.caFile in keysentry.yaml.',
    });
  } else if (summary.ca) {
    const count = summary.ca.certificates.length;
    items.push({
      area: 'network', status: 'ok', title: 'Extra certificate authorities',
      detail: `${count} extra ${count === 1 ? 'certificate is' : 'certificates are'} trusted from ${summary.ca.path}, in addition to the system roots.`,
    });
    for (const certificate of summary.ca.certificates.slice(0, MAX_LISTED_CERTIFICATES)) {
      const expiry = Date.parse(certificate.validTo);
      const expired = Number.isFinite(expiry) && expiry < now.getTime();
      items.push({
        area: 'network', status: expired ? 'warn' : 'info', title: `Trusted certificate: ${certificate.subject}`,
        detail: `Issued by ${certificate.issuer}. Valid until ${certificate.validTo}.`
          + (expired ? ' It has expired, so connections that rely on it will fail.' : '')
          + (certificate.isCa ? '' : ' It is not marked as a certificate authority, so it is trusted only for itself.'),
      });
    }
    if (count > MAX_LISTED_CERTIFICATES) {
      items.push({ area: 'network', status: 'info', title: 'More trusted certificates', detail: `${count - MAX_LISTED_CERTIFICATES} more certificates are not listed here.` });
    }
  } else {
    items.push({ area: 'network', status: 'info', title: 'Certificate authorities', detail: 'Only the system roots are trusted; no network.caFile is configured.' });
  }

  const offline = offlineNotice(summary.feeds);
  if (offline) items.push({ area: 'network', status: 'info', title: 'Offline mode', detail: offline });
  return items;
}
