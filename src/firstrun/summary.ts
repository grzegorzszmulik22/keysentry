import { isAbsolute, relative, resolve } from 'node:path';
import { fingerprint, makeHint } from '../core/fingerprint.js';
import { createRedactor } from '../core/redact.js';
import { TOKEN_CAPABILITIES } from '../doctor/capabilities.js';
import { TIER_ORDER, type FirstRunFinding, type FirstRunResult, type HostId } from '../types.js';
import type { RawHit } from './scan-files.js';
import type { HistoryScan } from './scan-history.js';

export interface FirstRunInput {
  root: string;
  files: { files: number; hits: RawHit[] };
  history: HistoryScan;
  deployTargets: { host: HostId; evidence: string }[];
  fingerprintKey: Buffer;
  elapsedMs: number;
}
const confidenceRank = { low: 0, medium: 1, high: 2 };

/** Consumes transient hits, replacing values with keyed identifiers and hints. Does not write state. */
export function buildFirstRun(input: FirstRunInput): FirstRunResult {
  const redactor = createRedactor();
  const all = [...input.files.hits, ...input.history.hits];
  // Register before processing metadata: a later hit's value can appear in an earlier filename.
  for (const hit of all) if (hit.value !== undefined) redactor.register(hit.value);
  function clean(text: string): string { return redactor.redact(text).replace(/[\x00-\x1f\x7f-\x9f]/g, '?'); }
  function cleanPath(path: string): string {
    const local = isAbsolute(path) ? relative(resolve(input.root), path) : path;
    if (local === '..' || local.startsWith('../') || local.startsWith('..\\') || isAbsolute(local)) return '(outside project)';
    return clean(local.replaceAll('\\', '/'));
  }
  const deployTargets = input.deployTargets.map(({ host, evidence }) => ({ host, evidence: cleanPath(evidence) }));
  const hosts = [...new Set(deployTargets.map(({ host }) => host))];
  const groups = new Map<string, { finding: FirstRunFinding; rank: number; present: boolean; deployed: boolean; locations: Set<string> }>();
  for (const hit of all) {
    const value = hit.value;
    if (value === undefined) continue;
    let id: string;
    let hint: string | null;
    try { id = fingerprint(value, input.fingerprintKey); hint = makeHint(value); }
    finally { delete hit.value; }
    if (!hit.isSecret) continue;
    const rank = confidenceRank[hit.confidence];
    let group = groups.get(id);
    if (!group) {
      group = { finding: { id, provider: hit.provider, tier: hit.tier, hint: hint === null ? null : clean(hint), locations: [], inGitHistory: false, likelyDeployedOn: [] },
        rank, present: false, deployed: false, locations: new Set() };
      groups.set(id, group);
    } else if (rank > group.rank || (rank === group.rank && TIER_ORDER.indexOf(hit.tier) < TIER_ORDER.indexOf(group.finding.tier))) {
      group.finding.provider = hit.provider; group.finding.tier = hit.tier; group.rank = rank;
    }
    group.present ||= hit.kind === 'file';
    group.deployed ||= hit.kind === 'file' && !hit.template;
    group.finding.inGitHistory ||= hit.kind === 'history';
    const location: FirstRunFinding['locations'][number] = { kind: hit.kind, path: cleanPath(hit.path),
      ...(hit.line === undefined ? {} : { line: hit.line }),
      ...(hit.commit === undefined ? {} : { commit: clean(hit.commit) }),
      ...(hit.committedAt === undefined ? {} : { committedAt: clean(hit.committedAt) }), stillPresent: hit.kind === 'file' };
    const identity = JSON.stringify(location);
    if (!group.locations.has(identity)) { group.locations.add(identity); group.finding.locations.push(location); }
  }
  const findings = [...groups.values()].map(({ finding, present, deployed }) => {
    for (const location of finding.locations) location.stillPresent = present;
    finding.likelyDeployedOn = deployed ? [...hosts] : [];
    return finding;
  }).sort((a, b) => TIER_ORDER.indexOf(a.tier) - TIER_ORDER.indexOf(b.tier) || a.id.localeCompare(b.id));
  const nextSteps: string[] = [];
  const committed = findings.filter((finding) => finding.inGitHistory).length;
  if (committed) nextSteps.push(`Rotate the ${committed} ${committed === 1 ? 'key that was' : 'keys that were'} committed to git; removing ${committed === 1 ? 'it' : 'them'} from the code is not enough.`);
  for (const host of hosts) {
    const capability = TOKEN_CAPABILITIES[host];
    if (!capability) continue;
    const recommended = capability.tokens.filter((token) => token.recommended);
    const token = recommended.find((candidate) => !candidate.canWrite) ?? recommended[0];
    if (token) nextSteps.push(`Connect ${capability.platform} with a ${token.name}; review what it can access first.`);
  }
  if (findings.length) nextSteps.push('See the key map.', 'Practise a breach with keysentry drill.', 'Arm autopilot after a successful drill.');
  if (!input.history.complete) nextSteps.push(`Git history scan is incomplete; scanned the last ${input.history.commits} commits.`);
  return { scannedFiles: input.files.files, scannedCommits: input.history.commits, historyComplete: input.history.complete,
    elapsedMs: input.elapsedMs, findings, deployTargets, nextSteps };
}
