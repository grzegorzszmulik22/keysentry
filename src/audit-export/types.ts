import type { AuditExportKind, AuditExportRecord } from '../types.js';

/** Mirrors one entry of `audit.export` in keysentry.yaml (src/cli/config.ts). Every field is non-secret. */
export type SyslogTarget = { kind: 'syslog'; id: string; host: string; port: number; appName: string };
export type OtlpTarget = { kind: 'otlp'; id: string; url: string };
export type S3Target = { kind: 's3'; id: string; endpoint: string; bucket: string; region: string; prefix: string };
export type WebhookTarget = { kind: 'webhook'; id: string; url: string; signing: 'ed25519' | 'hmac-sha256' };
export type AuditExportTarget = SyslogTarget | OtlpTarget | S3Target | WebhookTarget;

/** Vault names for export credentials: `audit-export/<target id>/<field>`. Values never leave memory except to their receiver. */
export const EXPORT_SECRET_FIELDS = {
  syslog: [],
  otlp: ['bearer', 'header'],
  s3: ['access-key-id', 'secret-access-key', 'session-token'],
  webhook: ['hmac-secret'],
} as const satisfies Record<AuditExportKind, readonly string[]>;
export type ExportSecretField = typeof EXPORT_SECRET_FIELDS[AuditExportKind][number];

export function exportSecretName(id: string, field: ExportSecretField): string {
  return `audit-export/${id}/${field}`;
}

/** A refusal to export at all (the log does not verify, or changed while it was read). */
export class AuditExportRefusedError extends Error {
  readonly code = 'AUDIT_EXPORT_REFUSED';
  constructor(message: string) {
    super(message);
    this.name = 'AuditExportRefusedError';
  }
}

/** One failed delivery attempt. Messages are fixed text: never a token, body, upstream text or credential-bearing URL. */
export class AuditExportError extends Error {
  readonly code = 'AUDIT_EXPORT_FAILED';
  constructor(message: string, readonly retryable: boolean, readonly retryAfterMs?: number) {
    super(message);
    this.name = 'AuditExportError';
  }
}

export interface DeliveryOutcome {
  /** Value-free notes the user should see, e.g. a receiver that rejected some records. */
  warnings?: string[];
}

/** Delivers batches to one configured target. Created per run; credentials are read on first use and kept in memory. */
export interface ExportSink {
  readonly target: AuditExportTarget;
  /** Value-free description of where records go (host and port, URL without query, bucket and prefix). */
  readonly destination: string;
  /** Resolves when the receiver accepted the batch; throws AuditExportError otherwise. */
  deliver(batch: readonly AuditExportRecord[]): Promise<DeliveryOutcome>;
  /** Value-free preview of one batch for `--dry-run`: no network, no credentials. */
  preview(batch: readonly AuditExportRecord[]): { location: string; bytes: number };
  /** Clears credential buffers held for this run. */
  dispose(): void;
}
