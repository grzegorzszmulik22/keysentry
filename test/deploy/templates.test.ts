import { readFile } from 'node:fs/promises';
import { describe, expect, test } from 'vitest';
import { parse } from 'yaml';

const root = new URL('../../', import.meta.url);
const read = (path: string) => readFile(new URL(path, root), 'utf8');
const yaml = async (path: string) => parse(await read(path));
const image = 'ghcr.io/grzenio22/keysentry';
const secrets = ['KEYSENTRY_VAULT_PASSPHRASE', 'KEYSENTRY_STATE_KEY', 'KEYSENTRY_WATCHER_KEY', 'KEYSENTRY_WATCHER_CONFIG', 'KEYSENTRY_WATCHER_VAULT'];
const cachePin = '55cc8345863c7cc4c66a329aec7e433d2d1c52a9';

describe('watcher deployment contracts (static; no Docker or platform calls)', () => {
  test('Dockerfile has two digest-pinned stages and builds with scripts disabled at install', async () => {
    const dockerfile = await read('Dockerfile');
    const from = dockerfile.match(/^FROM .+$/gm);
    expect(from).toEqual([
      'FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build',
      'FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:cb606325b7ec4af55462cb0b424a53b452a5b4a894ffe841fcf1048d216fb9f8',
    ]);
    expect(dockerfile).toContain('RUN npm ci --ignore-scripts');
    expect(dockerfile).toContain('RUN npm run release:build');
  });

  test('Dockerfile final stage runs as 65532 and copies only release files and the private empty state directory', async () => {
    const dockerfile = await read('Dockerfile');
    const final = dockerfile.slice(dockerfile.lastIndexOf('\nFROM '));
    expect(final).toMatch(/^USER 65532$/m);
    expect(final).toContain('ENTRYPOINT ["/nodejs/bin/node", "/app/keysentry.mjs", "watch"]');
    expect(final).toContain('VOLUME /data');
    expect(final).not.toMatch(/^(RUN|SHELL|HEALTHCHECK) /m);
    expect(final.match(/^COPY .+$/gm)).toEqual([
      'COPY --from=build /build/dist-release/out/keysentry.mjs /build/dist-release/out/release-manifest.json /app/',
      'COPY --from=build /build/LICENSE /build/NOTICE /app/',
      'COPY --from=build --chown=65532:65532 --chmod=0700 /watcher-state/ /data/',
    ]);
    expect(dockerfile).toContain('chmod 0700 /watcher-state');
    expect(final).toContain('KEYSENTRY_STATE_DIR=/data');
    expect(final).toContain('KEYSENTRY_VAULT=encrypted-file');
    expect(final).toContain('NODE_ENV=production');
    for (const name of secrets) expect(final).not.toMatch(new RegExp(`(?:ENV|ARG) ${name}`));
    for (const label of ['source', 'revision', 'licenses']) expect(final).toContain(`org.opencontainers.image.${label}`);
  });

  test('build context excludes state, generated files, repositories and local secrets', async () => {
    const ignored = (await read('.dockerignore')).split(/\r?\n/);
    for (const entry of ['node_modules', '.git', '.keysentry', 'logs', 'dist', 'dist-release', 'tools/probes', '.env', '.env.*']) {
      expect(ignored).toContain(entry);
    }
  });

  test.each([
    'deploy/compose/docker-compose.yml',
    'deploy/fly/fly.toml',
    'deploy/render/render.yaml',
    'deploy/railway/.railway/railway.ts',
    'deploy/github-actions/keysentry-watch.yml',
  ])('%s names every setup value needed for the first watcher start', async path => {
    const template = await read(path);
    for (const name of secrets) expect(template).toContain(name);
  });

  test('Compose runs a confined non-root worker with persistent state and env_file secrets', async () => {
    const compose = await yaml('deploy/compose/docker-compose.yml');
    const worker = compose.services.watcher;
    expect(worker.image).toBe(`${image}:1.0.0`);
    expect(worker.user).toBe('65532:65532');
    expect(worker.read_only).toBe(true);
    expect(worker.cap_drop).toEqual(['ALL']);
    expect(worker.security_opt).toEqual(['no-new-privileges:true']);
    expect(worker.tmpfs).toEqual(['/tmp']);
    expect(worker.env_file).toEqual(['.env']);
    expect(worker.environment).toMatchObject({ KEYSENTRY_STATE_DIR: '/data', KEYSENTRY_VAULT: 'encrypted-file' });
    expect(worker.volumes).toEqual(['keysentry-data:/data']);
    expect(compose.volumes).toHaveProperty('keysentry-data');
    expect(worker).not.toHaveProperty('ports');
    for (const name of secrets) expect(worker.environment).not.toHaveProperty(name);
  });

  test('Render worker mounts /data and requires every secret from setup without generated keys', async () => {
    const blueprint = await yaml('deploy/render/render.yaml');
    expect(blueprint.services).toHaveLength(1);
    const worker = blueprint.services[0];
    expect(worker).toMatchObject({ type: 'worker', runtime: 'image', image: { url: `${image}:1.0.0` }, disk: { mountPath: '/data', sizeGB: 1 } });
    for (const name of secrets) {
      expect(worker.envVars.find((entry: { key: string }) => entry.key === name)).toEqual({ key: name, sync: false });
    }
    expect(worker.envVars).not.toEqual(expect.arrayContaining([expect.objectContaining({ generateValue: true })]));
    expect(worker.envVars).toContainEqual({ key: 'KEYSENTRY_STATE_DIR', value: '/data' });
    expect(worker.envVars).toContainEqual({ key: 'KEYSENTRY_VAULT', value: 'encrypted-file' });
    expect(worker).not.toHaveProperty('healthCheckPath');
  });

  test('Fly worker has a persistent volume and no inbound services or plaintext secrets', async () => {
    const fly = await read('deploy/fly/fly.toml');
    expect(fly).toContain(`image = "${image}:1.0.0"`);
    expect(fly).toMatch(/source = "keysentry_data"/);
    expect(fly).toMatch(/destination = "\/data"/);
    expect(fly).toContain('KEYSENTRY_VAULT = "encrypted-file"');
    expect(fly).toContain('KEYSENTRY_STATE_DIR = "/data"');
    expect(fly).not.toMatch(/^\[(?:\[)?(?:http_service|services)/m);
    for (const name of secrets) expect(fly).not.toMatch(new RegExp(`^\\s*${name}\\s*=`, 'm'));
  });

  test('Railway uses the replacement IaC location and preserves externally supplied secrets', async () => {
    const railway = await read('deploy/railway/.railway/railway.ts');
    expect(railway).toContain(`image('${image}:1.0.0')`);
    expect(railway).toContain("volumeMounts: { '/data': data }");
    expect(railway).toContain("KEYSENTRY_STATE_DIR: '/data'");
    expect(railway).toContain("KEYSENTRY_VAULT: 'encrypted-file'");
    for (const name of secrets) expect(railway).toContain(`${name}: preserve()`);
  });

  test('unreleased image references explicitly require replacing the tag with the released digest', async () => {
    for (const path of ['deploy/compose/docker-compose.yml', 'deploy/render/render.yaml', 'deploy/fly/fly.toml', 'deploy/railway/.railway/railway.ts']) {
      expect(await read(path)).toContain('ghcr.io/grzenio22/keysentry@sha256:<release-digest>');
    }
  });

  test('Actions watcher uses read-only repository access, UTC schedule and immutable prefix-restored caches', async () => {
    const workflow = await yaml('deploy/github-actions/keysentry-watch.yml');
    expect(workflow.on.schedule).toEqual([{ cron: '*/10 * * * *', timezone: 'UTC' }]);
    expect(workflow.on).toHaveProperty('workflow_dispatch');
    expect(workflow.permissions).toEqual({ contents: 'read' });
    expect(workflow.concurrency['cancel-in-progress']).toBe(false);
    const job = workflow.jobs.watch;
    const restore = job.steps.find((step: { uses?: string }) => step.uses?.startsWith('actions/cache/restore@'));
    const save = job.steps.find((step: { uses?: string }) => step.uses?.startsWith('actions/cache/save@'));
    expect(restore.uses).toBe(`actions/cache/restore@${cachePin}`);
    expect(restore.with).toMatchObject({ path: '.keysentry', key: 'keysentry-state-${{ github.run_id }}', 'restore-keys': 'keysentry-state-\n' });
    expect(save.with).toMatchObject({ path: '.keysentry', key: 'keysentry-state-${{ github.run_id }}' });
    expect(save.if).toContain('always()');
    const run = job.steps.find((step: { id?: string }) => step.id === 'watch');
    for (const name of secrets) expect(run.env[name]).toBe(`\${{ secrets.${name} }}`);
    expect(run.run).toContain('node keysentry.mjs watch --once');
  });

  test('Actions watcher checks downloaded bundle bytes before running and never uses npx', async () => {
    const workflow = await yaml('deploy/github-actions/keysentry-watch.yml');
    const steps = workflow.jobs.watch.steps;
    const download = steps.find((step: { id?: string }) => step.id === 'release');
    expect(download.run).toContain('SHA256SUMS');
    expect(download.run).toContain('sha256sum --check');
    expect(download.run).toContain('--repo grzenio22/keysentry');
    expect(download.run).toContain('--pattern keysentry.mjs');
    expect(steps.indexOf(download)).toBeLessThan(steps.findIndex((step: { id?: string }) => step.id === 'watch'));
    expect(await read('deploy/github-actions/keysentry-watch.yml')).not.toMatch(/\bnpx\b/);
    for (const step of steps.filter((entry: { uses?: string }) => entry.uses)) expect(step.uses).toMatch(/@[a-f0-9]{40}$/);
  });

  test('image workflow builds attestations on tags and confines registry write permissions to its job', async () => {
    const workflow = await yaml('.github/workflows/image.yml');
    expect(workflow.on.push.tags).toEqual(['v*']);
    expect(workflow.permissions).toEqual({});
    const job = workflow.jobs.image;
    expect(job.permissions).toEqual({ contents: 'read', packages: 'write' });
    const push = job.steps.find((step: { id?: string }) => step.id === 'push');
    const login = job.steps.find((step: { id?: string }) => step.id === 'login');
    expect(push.if).toBe('${{ !github.event.repository.private }}');
    expect(login.if).toBe('${{ !github.event.repository.private }}');
    expect(push.run).toContain('docker buildx build');
    expect(push.run).toContain('--provenance=true');
    expect(push.run).toContain('--sbom=true');
    expect(push.run).toContain('--push');
    expect(push.run).toContain(image);
    const local = job.steps.find((step: { id?: string }) => step.id === 'private-build');
    expect(local.if).toBe('${{ github.event.repository.private }}');
    expect(local.run).not.toContain('--push');
    expect(JSON.stringify(job.steps)).not.toContain('docker/build-push-action');
    expect(login.run).toContain('--password-stdin');
    for (const step of job.steps.filter((entry: { uses?: string }) => entry.uses)) expect(step.uses).toMatch(/@[a-f0-9]{40}$/);
  });
});
