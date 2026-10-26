import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { silentLogger } from '../helpers/fake-http.js';
import { createDotenvHost } from '../../src/hosts/dotenv.js';

const tempRoots: string[] = [];
async function root(): Promise<string> {
  const dir = await mkdtemp(join(resolve('test/hosts'), '.dotenv-test-'));
  tempRoots.push(dir);
  return dir;
}
afterEach(async () => { await Promise.all(tempRoots.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });

describe('dotenv host', () => {
  it('replaces only targeted value spans and appends missing keys without backup files', async () => {
    const dir = await root();
    const fixture = '# untouched comment\r\n\r\nexport TOKEN = "old\\nvalue"  # keep inline\r\nSINGLE=\'single old\'\r\nMULTI="first\r\nsecond" # multiline\r\nBACK=`old back`\r\nPLAIN=old  # keep spacing\r\nUNCHANGED = bare value # untouched\r\nEMPTY=\r\n';
    const file = join(dir, '.env');
    await writeFile(file, fixture);
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    expect(service).toEqual({ host: 'dotenv', projectId: dir, projectName: relative(resolve(dir, '..'), dir), serviceId: file, serviceName: '.env', environmentId: '', environmentName: '' });
    expect(host.capabilities).toEqual({ readValues: true, batchWrite: true, redeploy: false });
    expect(await host.readVariables(service!)).toEqual([
      { name: 'TOKEN', value: 'old\nvalue', sealed: false },
      { name: 'SINGLE', value: 'single old', sealed: false },
      { name: 'MULTI', value: 'first\r\nsecond', sealed: false },
      { name: 'BACK', value: 'old back', sealed: false },
      { name: 'PLAIN', value: 'old', sealed: false },
      { name: 'UNCHANGED', value: 'bare value', sealed: false },
      { name: 'EMPTY', value: '', sealed: false },
    ]);
    await host.writeVariables(service!, { TOKEN: 'new\nvalue', SINGLE: 'single new', MULTI: 'new multiline', BACK: 'new back', PLAIN: 'with # hash', ADDED: 'added' }, { skipDeploy: true });
    expect(await readFile(file, 'utf8')).toBe('# untouched comment\r\n\r\nexport TOKEN = "new\\nvalue"  # keep inline\r\nSINGLE=\'single new\'\r\nMULTI="new multiline" # multiline\r\nBACK=`new back`\r\nPLAIN="with # hash"  # keep spacing\r\nUNCHANGED = bare value # untouched\r\nEMPTY=\r\nADDED=added\r\n');
    expect(await readdir(dir)).toEqual(['.env']);
    expect(await host.redeploy(service!)).toBeNull();
  });

  it('skips templates and excluded directories and deduplicates overlapping roots', async () => {
    const dir = await root();
    for (const name of ['node_modules', '.git', 'dist', 'build', '.keysentry', 'nested']) {
      await mkdir(join(dir, name));
      await writeFile(join(dir, name, '.env'), 'KEY=value\n');
    }
    for (const name of ['.env', '.env.local', '.env.example', '.env.sample', '.env.template', '.env.dist', 'other.env']) {
      await writeFile(join(dir, name), 'KEY=value\n');
    }
    const host = createDotenvHost({ roots: [dir, join(dir, 'nested')], log: silentLogger });
    expect((await host.listServices()).map((s) => relative(dir, s.serviceId)).sort()).toEqual(['.env', '.env.local', join('nested', '.env')].sort());
    const templates = createDotenvHost({ roots: [dir], includeTemplates: true, log: silentLogger });
    expect((await templates.listServices()).map((s) => s.serviceName).sort()).toEqual(['.env', '.env.local', '.env.example', '.env.sample', '.env.template', '.env.dist', join('nested', '.env')].sort());
  });

  it('round-trips quotes, literal escapes, multiline values, BOM and a missing final newline', async () => {
    const dir = await root();
    const file = join(dir, '.env');
    await writeFile(file, '\uFEFFexport KEY=old\nDUP=first\nDUP=last\nKEEP=unchanged');
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    const value = 'a "quote" \\n literal\nreal newline\rreturn #';
    await host.writeVariables(service!, { KEY: value, DUP: 'new', NEW: "single' and `tick`" }, { skipDeploy: false });
    expect(await host.readVariables(service!)).toEqual([
      { name: 'KEY', value, sealed: false },
      { name: 'DUP', value: 'new', sealed: false },
      { name: 'KEEP', value: 'unchanged', sealed: false },
      { name: 'NEW', value: "single' and `tick`", sealed: false },
    ]);
    const updated = await readFile(file, 'utf8');
    expect(updated.startsWith('\uFEFFexport KEY=')).toBe(true);
    expect(updated).toContain('\nDUP=new\nDUP=new\nKEEP=unchanged\n');
    expect(await readdir(dir)).toEqual(['.env']);
  });

  it('leaves files unchanged for empty writes and rejects invalid names without leaking values', async () => {
    const dir = await root();
    const file = join(dir, '.env');
    await writeFile(file, 'KEY=old');
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    await host.writeVariables(service!, {}, { skipDeploy: true });
    expect(await readFile(file, 'utf8')).toBe('KEY=old');
    const error = await host.writeVariables(service!, { 'INVALID\nKEY': 'secret-error-value' }, { skipDeploy: true }).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).not.toContain('secret-error-value');
    expect(await readFile(file, 'utf8')).toBe('KEY=old');
    expect(await readdir(dir)).toEqual(['.env']);
  });

  it('rejects files outside configured roots and skips symlink directories', async () => {
    const dir = await root();
    const outside = await root();
    const file = join(outside, '.env');
    await writeFile(file, 'KEY=outside');
    await symlink(outside, join(dir, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    expect(await host.listServices()).toEqual([]);
    const ref = { host: 'dotenv' as const, projectId: dir, projectName: '', serviceId: file, serviceName: '.env', environmentId: '', environmentName: '' };
    await expect(host.writeVariables(ref, { KEY: 'changed' }, { skipDeploy: true })).rejects.toThrow();
    expect(await readFile(file, 'utf8')).toBe('KEY=outside');
  });

  it.each(['\r', '\n', '\r\n', '\u2028', '\u2029'])('preserves untargeted assignments with line separator %j', async (newline) => {
    const dir = await root();
    const file = join(dir, '.env');
    await writeFile(file, `KEY=old${newline}AFTER=keep${newline}`);
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    expect(await host.readVariables(service!)).toEqual([
      { name: 'KEY', value: 'old', sealed: false },
      { name: 'AFTER', value: 'keep', sealed: false },
    ]);
    await host.writeVariables(service!, { KEY: 'new', NEW: 'added' }, { skipDeploy: true });
    expect(await readFile(file, 'utf8')).toBe(`KEY=new${newline}AFTER=keep${newline}NEW=added${newline}`);
  });

  it.each(['', '\n', '\r\n'])('replaces empty values at EOF and before a final newline %j', async (newline) => {
    const dir = await root();
    const file = join(dir, '.env');
    await writeFile(file, `EMPTY=${newline}`);
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    expect(await host.readVariables(service!)).toEqual([{ name: 'EMPTY', value: '', sealed: false }]);
    await host.writeVariables(service!, { EMPTY: 'new' }, { skipDeploy: true });
    expect(await readFile(file, 'utf8')).toBe(`EMPTY=new${newline}`);
  });

  it('rejects invalid UTF-8 before rewriting so unrelated raw bytes cannot change', async () => {
    const dir = await root();
    const file = join(dir, '.env');
    const original = Buffer.concat([Buffer.from('KEEP='), Buffer.from([0xff]), Buffer.from('\nKEY=old\n')]);
    await writeFile(file, original);
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    await expect(host.writeVariables(service!, { KEY: 'new' }, { skipDeploy: true })).rejects.toThrow();
    expect(await readFile(file)).toEqual(original);
    expect(await readdir(dir)).toEqual(['.env']);
  });
});
