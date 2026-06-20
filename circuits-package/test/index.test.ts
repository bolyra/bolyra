import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import {
  getCircuitArtifacts,
  getArtifactsDir,
  getVerificationKey,
  listAvailableCircuits,
  CIRCUITS,
  CircuitName,
} from '../src/index';

describe('@bolyra/circuits', () => {
  const artifactsDir = getArtifactsDir();
  const artifactsExist = fs.existsSync(
    path.join(artifactsDir, 'HumanUniqueness', 'HumanUniqueness.wasm'),
  );

  describe('getArtifactsDir()', () => {
    it('returns a string ending with artifacts/', () => {
      const dir = getArtifactsDir();
      expect(dir).to.be.a('string');
      expect(dir).to.match(/artifacts$/);
    });

    it('returns an absolute path', () => {
      const dir = getArtifactsDir();
      expect(path.isAbsolute(dir)).to.be.true;
    });
  });

  describe('CIRCUITS constant', () => {
    it('lists all three production circuits', () => {
      expect(Object.keys(CIRCUITS)).to.have.members([
        'HumanUniqueness',
        'AgentPolicy',
        'Delegation',
      ]);
    });

    it('all circuits support groth16', () => {
      for (const systems of Object.values(CIRCUITS)) {
        expect(systems).to.include('groth16');
      }
    });
  });

  describe('getCircuitArtifacts()', () => {
    it('throws on invalid circuit name', () => {
      expect(() =>
        getCircuitArtifacts('InvalidCircuit' as CircuitName),
      ).to.throw(/Unknown circuit/);
    });

    // Tests that require artifacts on disk
    const circuits: CircuitName[] = ['HumanUniqueness', 'AgentPolicy', 'Delegation'];

    for (const circuit of circuits) {
      describe(`${circuit} (groth16)`, () => {
        (artifactsExist ? it : it.skip)(
          'returns paths for all three artifact types',
          () => {
            const result = getCircuitArtifacts(circuit, 'groth16');
            expect(result).to.have.property('wasm').that.is.a('string');
            expect(result).to.have.property('zkey').that.is.a('string');
            expect(result).to.have.property('vkey').that.is.a('string');
          },
        );

        (artifactsExist ? it : it.skip)(
          'all returned paths exist on disk',
          () => {
            const result = getCircuitArtifacts(circuit, 'groth16');
            expect(fs.existsSync(result.wasm), `wasm exists: ${result.wasm}`).to.be.true;
            expect(fs.existsSync(result.zkey), `zkey exists: ${result.zkey}`).to.be.true;
            expect(fs.existsSync(result.vkey), `vkey exists: ${result.vkey}`).to.be.true;
          },
        );

        (artifactsExist ? it : it.skip)(
          'wasm path ends with .wasm',
          () => {
            const result = getCircuitArtifacts(circuit, 'groth16');
            expect(result.wasm).to.match(/\.wasm$/);
          },
        );

        (artifactsExist ? it : it.skip)(
          'zkey path ends with _groth16.zkey',
          () => {
            const result = getCircuitArtifacts(circuit, 'groth16');
            expect(result.zkey).to.match(/_groth16\.zkey$/);
          },
        );

        (artifactsExist ? it : it.skip)(
          'vkey path ends with _groth16_vkey.json',
          () => {
            const result = getCircuitArtifacts(circuit, 'groth16');
            expect(result.vkey).to.match(/_groth16_vkey\.json$/);
          },
        );
      });
    }
  });

  describe('getVerificationKey()', () => {
    (artifactsExist ? it : it.skip)(
      'returns a parsed JSON object for HumanUniqueness',
      () => {
        const vkey = getVerificationKey('HumanUniqueness', 'groth16');
        expect(vkey).to.be.an('object');
        expect(vkey).to.have.property('protocol');
      },
    );

    (artifactsExist ? it : it.skip)(
      'caches results on repeated calls',
      () => {
        const vkey1 = getVerificationKey('AgentPolicy', 'groth16');
        const vkey2 = getVerificationKey('AgentPolicy', 'groth16');
        expect(vkey1).to.equal(vkey2); // same reference
      },
    );
  });

  describe('listAvailableCircuits()', () => {
    it('returns an array of circuit/system pairs', () => {
      const list = listAvailableCircuits();
      expect(list).to.be.an('array');
      expect(list.length).to.be.greaterThan(0);

      for (const entry of list) {
        expect(entry).to.have.property('circuit').that.is.a('string');
        expect(entry).to.have.property('system').that.is.a('string');
      }
    });

    it('includes all three circuits with groth16', () => {
      const list = listAvailableCircuits();
      const groth16Circuits = list
        .filter((e) => e.system === 'groth16')
        .map((e) => e.circuit);
      expect(groth16Circuits).to.include.members([
        'HumanUniqueness',
        'AgentPolicy',
        'Delegation',
      ]);
    });
  });

  describe('checksum integrity', () => {
    (artifactsExist ? it : it.skip)(
      'checksums.sha256 file exists in artifacts/',
      () => {
        const checksumFile = path.join(artifactsDir, 'checksums.sha256');
        expect(fs.existsSync(checksumFile), 'checksums.sha256 exists').to.be.true;
        const content = fs.readFileSync(checksumFile, 'utf-8');
        expect(content.trim().length).to.be.greaterThan(0);
      },
    );
  });
});
