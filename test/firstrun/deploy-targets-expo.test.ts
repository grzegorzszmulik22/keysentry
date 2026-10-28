// fix-phase6 L4: app.json is also Expo's config file, so it is Heroku evidence only beside heroku.yml or a Procfile.
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { detectDeployTargets } from '../../src/firstrun/deploy-targets.js';

const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
async function project(files: string[]): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'keysentry-targets-')); dirs.push(root);
  for (const file of files) await writeFile(join(root, file), '{}');
  return root;
}

describe('app.json evidence', () => {
  it('does not suggest Heroku for an Expo project with only app.json', async () => {
    expect(await detectDeployTargets(await project(['app.json', 'eas.json']))).toEqual([]);
  });
  it('keeps app.json as corroborating Heroku evidence beside a Procfile or heroku.yml', async () => {
    expect(await detectDeployTargets(await project(['app.json', 'Procfile']))).toEqual([
      { host: 'heroku', evidence: 'app.json' }, { host: 'heroku', evidence: 'Procfile' },
    ]);
    expect(await detectDeployTargets(await project(['heroku.yml']))).toEqual([{ host: 'heroku', evidence: 'heroku.yml' }]);
  });
});
