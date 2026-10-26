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
      { name: 'MULTI', value: 'first\nsecond', sealed: false },
      { name: 'BACK', value: 'old back', sealed: false },
      { name: 'PLAIN', value: 'old', sealed: false },
      { name: 'UNCHANGED', value: 'bare value', sealed: false },
      { name: 'EMPTY', value: '', sealed: false },
    ]);
    await host.writeVariables(service!, { TOKEN: 'new\nvalue', SINGLE: 'single new', MULTI: 'new multiline', BACK: 'new back', PLAIN: 'with # hash', ADDED: 'added' }, { skipDeploy: true });
    expect(await readFile(file, 'utf8')).toBe('# untouched comment\r\n\r\nexport TOKEN = "new\\nvalue"  # keep inline\r\nSINGLE=\'single new\'\r\nMULTI="new multiline" # multiline\r\nBACK=`new back`\r\nPLAIN=\'with # hash\'  # keep spacing\r\nUNCHANGED = bare value # untouched\r\nEMPTY=\r\nADDED=added\r\n');
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
    const value = 'a quote and \\ literal\nreal newline\rreturn #';
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

  it.each(['\r', '\n', '\r\n'])('preserves untargeted assignments with line separator %j', async (newline) => {
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
    const service = { host: 'dotenv' as const, projectId: dir, projectName: '', serviceId: file, serviceName: '.env', environmentId: '', environmentName: '' };
    expect(await host.listServices()).toEqual([]);
    await expect(host.writeVariables(service!, { KEY: 'new' }, { skipDeploy: true })).rejects.toThrow();
    expect(await readFile(file)).toEqual(original);
    expect(await readdir(dir)).toEqual(['.env']);
  });

  it('reads the review probe and literal quoted escapes exactly as dotenv does', async () => {
    const dir = await root();
    const file = join(dir, '.env');
    await writeFile(file, String.raw`PROBE="pa\\ss\"word"
DOUBLE="one\\two\"three\nfour\rfive\tend"
SINGLE='one\\two\'three\nfour'
BACK=\`one\\two\nfour\`
UNQUOTED=   trimmed value   # comment
HASH=before#comment
DOLLAR=$UNCHANGED
` .replaceAll('\\`', '`'));
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    expect(await host.readVariables(service!)).toEqual([
      { name: 'PROBE', value: String.raw`pa\\ss\"word`, sealed: false },
      { name: 'DOUBLE', value: String.raw`one\\two\"three` + '\nfour\rfive\\tend', sealed: false },
      { name: 'SINGLE', value: String.raw`one\\two\'three\nfour`, sealed: false },
      { name: 'BACK', value: String.raw`one\\two\nfour`, sealed: false },
      { name: 'UNQUOTED', value: 'trimmed value', sealed: false },
      { name: 'HASH', value: 'before', sealed: false },
      { name: 'DOLLAR', value: '$UNCHANGED', sealed: false },
    ]);
  });

  it.each([
    ['double', '"old"', 'pa\\ss"word', '"pa\\ss"word"'],
    ['single', "'old'", 'pa\\ss"word', "'pa\\ss\"word'"],
    ['JSON', '"old"', '{"private_key":"-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\\n"}', "'{\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\\n\"}'"],
    ['hash', 'old', 'with # hash', "'with # hash'"],
    ['single quote', 'old', "has' # hash", "`has' # hash`"],
    ['backtick', 'old', 'has` # hash', "'has` # hash'"],
    ['single and backtick quotes', 'old', 'has\'` # $HOME', '"has\'` # $HOME"'],
    ['literal carriage escape', '"old"', 'literal\\rreturn', "'literal\\rreturn'"],
    ['multiline literal newline escape', '"old"', 'literal\\n and\nnewline', "'literal\\n and\nnewline'"],
    ['multiline literal carriage escape', 'old', 'literal\\r and\nnewline', "'literal\\r and\nnewline'"],
    ['multiline JSON with literal escapes', '"old"', '{\n  "private_key": "first\\nsecond\\n"\n}', "'{\n  \"private_key\": \"first\\nsecond\\n\"\n}'"],
    ['dollar', 'old', '$HOME', '$HOME'],
    ['real newlines', 'old', 'one\ntwo\rthree', '"one\\ntwo\\rthree"'],
  ])('writes %s without changing the value under dotenv parsing', async (_label, before, value, encoded) => {
    const dir = await root();
    const file = join(dir, '.env');
    await writeFile(file, `KEY=${before} # keep\nAFTER=keep\n`);
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    await host.writeVariables(service!, { KEY: value! }, { skipDeploy: true });
    expect(await readFile(file, 'utf8')).toBe(`KEY=${encoded} # keep\nAFTER=keep\n`);
    expect(await host.readVariables(service!)).toEqual([
      { name: 'KEY', value, sealed: false }, { name: 'AFTER', value: 'keep', sealed: false },
    ]);
  });

  it.each(['literal\\n and\rreturn', 'literal\\r and\r\nnewline', "all'`quotes\\n #"])(
    'refuses an unrepresentable write without changing the original or leaking the value', async (value) => {
      const dir = await root();
      const file = join(dir, '.env');
      await writeFile(file, 'KEY=old\n');
      const host = createDotenvHost({ roots: [dir], log: silentLogger });
      const [service] = await host.listServices();
      const error = await host.writeVariables(service!, { KEY: value }, { skipDeploy: true }).catch((err: unknown) => err);
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).toMatch(/round.trip|represent/i);
      expect(String(error)).not.toContain(value);
      expect(await readFile(file, 'utf8')).toBe('KEY=old\n');
      expect(await readdir(dir)).toEqual(['.env']);
    },
  );

  it('reads multiline quoted literals without expanding escapes, comments, or interpolation', async () => {
    const dir = await root();
    const file = join(dir, '.env');
    await writeFile(file, "SINGLE='first\\n # $HOME\n\"second\" `tick`\\r' # keep\nBACK=`first\\n\nsecond\\r`\nDOUBLE=\"first\\n\nsecond\\r\"\nAFTER=keep\n");
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    expect(await host.readVariables(service!)).toEqual([
      { name: 'SINGLE', value: 'first\\n # $HOME\n"second" `tick`\\r', sealed: false },
      { name: 'BACK', value: 'first\\n\nsecond\\r', sealed: false },
      { name: 'DOUBLE', value: 'first\n\nsecond\r', sealed: false },
      { name: 'AFTER', value: 'keep', sealed: false },
    ]);
  });

  it('appends a multiline literal escape value using single quotes and preserves the existing bytes', async () => {
    const dir = await root();
    const file = join(dir, '.env');
    await writeFile(file, '\uFEFFKEEP="unchanged" # preserved\r\n');
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    await host.writeVariables(service!, { NEW: '  first\\n\nsecond\\r # $HOME  ' }, { skipDeploy: true });
    expect(await readFile(file, 'utf8')).toBe('\uFEFFKEEP="unchanged" # preserved\r\nNEW=\'  first\\n\nsecond\\r # $HOME  \'\r\n');
    expect(await host.readVariables(service!)).toEqual([
      { name: 'KEEP', value: 'unchanged', sealed: false },
      { name: 'NEW', value: '  first\\n\nsecond\\r # $HOME  ', sealed: false },
    ]);
    expect(await readdir(dir)).toEqual(['.env']);
  });

  it('normalizes CRLF inside quoted values and supports dotenv colon and numeric-key syntax', async () => {
    const dir = await root();
    const file = join(dir, '.env');
    await writeFile(file, 'export 1KEY: "one\r\ntwo"\r\nSINGLE=\'three\rfour\'\r\nIGNORED TEXT\r\n');
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    expect(await host.readVariables(service!)).toEqual([
      { name: '1KEY', value: 'one\ntwo', sealed: false }, { name: 'SINGLE', value: 'three\nfour', sealed: false },
    ]);
  });

  it('skips an invalid UTF-8 file individually, warns by file, and continues scanning', async () => {
    const dir = await root();
    const bad = join(dir, '.env.enc');
    await writeFile(bad, Buffer.from([0xff, 0xfe, 0x41]));
    await writeFile(join(dir, '.env'), 'KEY=readable\n');
    await writeFile(join(dir, '.env.local'), 'KEY=also-readable\n');
    const warnings: unknown[] = [];
    const host = createDotenvHost({ roots: [dir], log: { ...silentLogger, warn: (...args) => { warnings.push(args); } } });
    const services = await host.listServices();
    expect(services.map((service) => service.serviceName)).toEqual(['.env', '.env.local']);
    expect(warnings).toHaveLength(1);
    expect(JSON.stringify(warnings)).toContain(bad.replaceAll('\\', '\\\\'));
    expect(await host.readVariables(services[0]!)).toEqual([{ name: 'KEY', value: 'readable', sealed: false }]);
  });

  it('deletes stale temp files next to discovered env files and never scans them', async () => {
    const dir = await root();
    await writeFile(join(dir, '.env'), 'KEY=old\n');
    await writeFile(join(dir, '.env.keysentry-stale.tmp'), 'KEY=stale\n');
    await writeFile(join(dir, '.env.local.keysentry-stale.tmp'), 'KEY=stale\n');
    await writeFile(join(dir, '.keysentry-legacy.tmp'), 'KEY=stale\n');
    await writeFile(join(dir, 'keep.tmp'), 'keep');
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    expect((await host.listServices()).map((service) => service.serviceName)).toEqual(['.env']);
    expect((await readdir(dir)).sort()).toEqual(['.env', 'keep.tmp']);
  });

  it.each([
    ['KEY=old # note `\nAFTER=keep\n', '`', "KEY='`' # note `\nAFTER=keep\n", [{ name: 'AFTER', value: 'keep', sealed: false }]],
    ["KEY='old'\nAFTER=ends'\n", 'ends\\', "KEY=`ends\\`\nAFTER=ends'\n", [{ name: 'AFTER', value: "ends'", sealed: false }]],
    ['KEY=old\nAFTER=keep\nOTHER=ends`\n', '`', "KEY='`'\nAFTER=keep\nOTHER=ends`\n", [{ name: 'AFTER', value: 'keep', sealed: false }, { name: 'OTHER', value: 'ends`', sealed: false }]],
  ] as const)('chooses quotes using the actual surrounding file to preserve other variables (%j)', async (source, value, expected, rest) => {
    const dir = await root();
    const file = join(dir, '.env');
    await writeFile(file, source);
    const host = createDotenvHost({ roots: [dir], log: silentLogger });
    const [service] = await host.listServices();
    await host.writeVariables(service!, { KEY: value }, { skipDeploy: true });
    expect(await readFile(file, 'utf8')).toBe(expected);
    expect(await host.readVariables(service!)).toEqual([{ name: 'KEY', value, sealed: false }, ...rest]);
  });
});
