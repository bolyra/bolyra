import { spawn } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { parse as parseYaml } from 'yaml';
import { learn } from '../src/learn';

const MOCK = (mode: string) =>
  `npx tsx ${path.resolve(__dirname, 'mock-learn-server.ts')} ${mode}`;
const SHIELD_BIN = path.resolve(__dirname, '../dist/cli.js');

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shield-learn-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('@bolyra/shield --learn', () => {
  test('generates shield.yaml with defaultDeny and READ_DATA policies for every tool', async () => {
    const outPath = path.join(tmpDir, 'shield.yaml');
    const result = await learn({ server: MOCK('single'), outPath });

    expect(result.tools.map(t => t.name).sort()).toEqual(['read_file', 'write_file']);
    expect(result.outPath).toBe(outPath);

    const doc = parseYaml(fs.readFileSync(outPath, 'utf-8'));
    expect(doc.defaultDeny).toBe(true);
    expect(doc.tools.read_file).toEqual({ requireBitmask: 1 });
    expect(doc.tools.write_file).toEqual({ requireBitmask: 1 });
  });

  test('generated file carries a _generated provenance marker', async () => {
    const outPath = path.join(tmpDir, 'shield.yaml');
    await learn({ server: MOCK('single'), outPath });

    const doc = parseYaml(fs.readFileSync(outPath, 'utf-8'));
    expect(doc._generated).toBeDefined();
    expect(doc._generated.by).toContain('--learn');
    expect(doc._generated.server).toBe(MOCK('single'));
    expect(doc._generated.date).toMatch(/^\d{4}-\d{2}-\d{2}/);
  });

  test('collects tools across paginated tools/list responses', async () => {
    const outPath = path.join(tmpDir, 'shield.yaml');
    const result = await learn({ server: MOCK('paginated'), outPath });

    expect(result.tools.map(t => t.name).sort()).toEqual(['read_file', 'write_file']);
    const doc = parseYaml(fs.readFileSync(outPath, 'utf-8'));
    expect(Object.keys(doc.tools).sort()).toEqual(['read_file', 'write_file']);
  });

  test('errors when pagination exceeds the page cap', async () => {
    const outPath = path.join(tmpDir, 'shield.yaml');
    await expect(
      learn({ server: MOCK('infinite'), outPath, maxPages: 5 }),
    ).rejects.toThrow(/pagination/i);
    expect(fs.existsSync(outPath)).toBe(false);
  });

  test('times out against an unresponsive server', async () => {
    const outPath = path.join(tmpDir, 'shield.yaml');
    await expect(
      learn({ server: MOCK('silent'), outPath, timeoutMs: 4000 }),
    ).rejects.toThrow(/timed out/i);
    expect(fs.existsSync(outPath)).toBe(false);
  }, 12000);

  test('refuses to overwrite an existing config file (O_EXCL)', async () => {
    const outPath = path.join(tmpDir, 'shield.yaml');
    fs.writeFileSync(outPath, 'defaultDeny: false\n');

    await expect(
      learn({ server: MOCK('single'), outPath }),
    ).rejects.toThrow(/exists/i);
    expect(fs.readFileSync(outPath, 'utf-8')).toBe('defaultDeny: false\n');
  });

  test('CLI: --learn writes the config and exits 0', done => {
    const outPath = path.join(tmpDir, 'shield.yaml');
    const child = spawn('node', [
      SHIELD_BIN,
      '--learn',
      '--server', MOCK('single'),
      '--config', outPath,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });

    child.on('exit', code => {
      try {
        expect(code).toBe(0);
        const doc = parseYaml(fs.readFileSync(outPath, 'utf-8'));
        expect(doc.defaultDeny).toBe(true);
        expect(Object.keys(doc.tools).sort()).toEqual(['read_file', 'write_file']);
        done();
      } catch (err) {
        done(err as Error);
      }
    });
  });
});
