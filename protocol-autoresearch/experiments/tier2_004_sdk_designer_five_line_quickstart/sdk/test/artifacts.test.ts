import { describe, it, beforeEach, afterEach } from 'mocha';
import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ArtifactResolver, ArtifactNotFoundError } from '../src/artifacts';

describe('ArtifactResolver', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-artifacts-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.BOLYRA_ARTIFACTS_DIR;
  });

  const ALL_ARTIFACTS = [
    'HumanUniqueness.wasm',
    'HumanUniqueness_final.zkey',
    'AgentPolicy.wasm',
    'AgentPolicy_final.zkey',
    'Delegation.wasm',
    'Delegation_final.zkey',
    'HumanUniqueness_vkey.json',
    'AgentPolicy_vkey.json',
    'Delegation_vkey.json',
  ];

  function populateArtifacts(dir: string): void {
    for (const name of ALL_ARTIFACTS) {
      fs.writeFileSync(path.join(dir, name), 'mock-artifact');
    }
  }

  it('resolves all artifacts from explicit artifactsDir', () => {
    populateArtifacts(tmpDir);
    const resolver = new ArtifactResolver(tmpDir);
    const resolved = resolver.resolve();

    expect(resolved.humanWasm).to.equal(path.join(tmpDir, 'HumanUniqueness.wasm'));
    expect(resolved.humanZkey).to.equal(path.join(tmpDir, 'HumanUniqueness_final.zkey'));
    expect(resolved.agentWasm).to.equal(path.join(tmpDir, 'AgentPolicy.wasm'));
    expect(resolved.agentZkey).to.equal(path.join(tmpDir, 'AgentPolicy_final.zkey'));
    expect(resolved.delegationWasm).to.equal(path.join(tmpDir, 'Delegation.wasm'));
    expect(resolved.delegationZkey).to.equal(path.join(tmpDir, 'Delegation_final.zkey'));
    expect(resolved.humanVkey).to.equal(path.join(tmpDir, 'HumanUniqueness_vkey.json'));
    expect(resolved.agentVkey).to.equal(path.join(tmpDir, 'AgentPolicy_vkey.json'));
    expect(resolved.delegationVkey).to.equal(path.join(tmpDir, 'Delegation_vkey.json'));
  });

  it('resolves from BOLYRA_ARTIFACTS_DIR env var', () => {
    populateArtifacts(tmpDir);
    process.env.BOLYRA_ARTIFACTS_DIR = tmpDir;
    const resolver = new ArtifactResolver();
    const resolved = resolver.resolve();

    expect(resolved.humanWasm).to.equal(path.join(tmpDir, 'HumanUniqueness.wasm'));
  });

  it('prefers explicit artifactsDir over env var', () => {
    const altDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-alt-'));
    populateArtifacts(tmpDir);
    populateArtifacts(altDir);
    process.env.BOLYRA_ARTIFACTS_DIR = altDir;

    const resolver = new ArtifactResolver(tmpDir);
    const resolved = resolver.resolve();

    expect(resolved.humanWasm).to.equal(path.join(tmpDir, 'HumanUniqueness.wasm'));
    fs.rmSync(altDir, { recursive: true, force: true });
  });

  it('throws ArtifactNotFoundError with actionable message on miss', () => {
    const resolver = new ArtifactResolver(tmpDir);

    try {
      resolver.resolve();
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).to.be.instanceOf(ArtifactNotFoundError);
      const msg = (err as Error).message;
      expect(msg).to.include('HumanUniqueness.wasm');
      expect(msg).to.include('npm run compile:circuits');
      expect(msg).to.include('BOLYRA_ARTIFACTS_DIR');
    }
  });

  it('resolveSingle returns path for a single artifact key', () => {
    populateArtifacts(tmpDir);
    const resolver = new ArtifactResolver(tmpDir);
    const p = resolver.resolveSingle('humanWasm');
    expect(p).to.equal(path.join(tmpDir, 'HumanUniqueness.wasm'));
  });

  it('resolveSingle throws for missing single artifact', () => {
    const resolver = new ArtifactResolver(tmpDir);
    expect(() => resolver.resolveSingle('humanWasm')).to.throw(ArtifactNotFoundError);
  });
});
