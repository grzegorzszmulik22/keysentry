import { get } from '../api.js';
import { emptyState } from '../components.js';
import { count, element, hostName, routeLink, section } from './components-a.js';
import type { OverviewResponse } from './components-a.js';

export async function renderHome(): Promise<HTMLElement> {
  const overview = await get<OverviewResponse>('overview');
  const page = element('div', undefined, 'screen-a overview-screen');
  if (!overview.firstRun && overview.keys === 0) page.append(emptyState('Run keysentry in your project folder to see your keys.'));
  else {
    page.append(element('p', `This project has ${count(overview.keys, 'key')}. ${count(overview.inGitHistory, 'key')} ${overview.inGitHistory === 1 ? 'appears' : 'appear'} in git history.`));
    if (overview.needsRotation) page.append(element('p', `${count(overview.needsRotation, 'key')} ${overview.needsRotation === 1 ? 'needs' : 'need'} rotation. Review the places each key is used before choosing a change.`));
  }

  const scan = overview.firstRun;
  if (scan) {
    page.append(element('p', `Scanned ${count(scan.scannedFiles, 'file')} and ${count(scan.scannedCommits, 'commit')}. ${scan.historyComplete ? 'The git history scan is complete.' : 'The git history scan is incomplete; there may be more keys in older commits.'}`, 'screen-a-muted'));
    if (scan.deployTargets.length) {
      const targets = [...new Set(scan.deployTargets.map(target => hostName(target.host)))];
      const deployment = section('Likely deployment platforms');
      deployment.append(element('p', `Project files suggest this project deploys to ${targets.join(', ')}.`));
      const evidence = element('ul');
      for (const target of scan.deployTargets) {
        const item = element('li', `${hostName(target.host)}: `); item.append(element('code', target.evidence)); evidence.append(item);
      }
      deployment.append(evidence); page.append(deployment);
    } else page.append(element('p', 'No deployment platforms were identified from project files.'));
  }
  page.append(element('p', overview.connectedPlatforms.length ? `Connected platforms: ${overview.connectedPlatforms.map(hostName).join(', ')}.` : 'No platforms connected yet. Connect Railway, Vercel, Render or Fly to see where your keys are deployed.'));
  page.append(element('p', `Autopilot is ${overview.autopilot === 'alert-only' ? 'in alert-only mode' : overview.autopilot}.`));

  const nextSteps = overview.nextSteps.length ? overview.nextSteps : scan?.nextSteps ?? [];
  if (nextSteps.length) {
    const next = section('Next steps'); const list = element('ol');
    for (const text of nextSteps) list.append(element('li', text));
    next.append(list); page.append(next);
  }
  const links = element('nav', undefined, 'screen-a-links'); links.setAttribute('aria-label', 'Project next steps');
  for (const [title, route] of [['See your keys', 'keys'], ['Connect a platform', 'connect'], ['Review access', 'access'], ['Review network', 'network'], ['Practise a rotation', 'rotate'], ['Review autopilot', 'autopilot']] as const) links.append(routeLink(title, route));
  page.append(links); return page;
}
