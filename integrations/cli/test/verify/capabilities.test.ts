import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Permission } from '@bolyra/sdk';
import {
  DEFAULT_CAPABILITY_MAP,
  loadCapabilityMap,
  requiredBits,
} from '../../src/verify/capabilities';
import { isVerifyDenial } from '../../src/verify/verdict';

const READ_DATA = 1n << BigInt(Permission.READ_DATA); // bit 0
const WRITE_DATA = 1n << BigInt(Permission.WRITE_DATA); // bit 1
const ACCESS_PII = 1n << BigInt(Permission.ACCESS_PII); // bit 7

async function writeMapFile(contents: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'bolyra-capmap-'));
  const file = path.join(dir, 'capability-map.json');
  await fs.writeFile(file, contents, 'utf8');
  return file;
}

describe('DEFAULT_CAPABILITY_MAP', () => {
  it('covers the mcp_agent_mail vocabulary', () => {
    expect(DEFAULT_CAPABILITY_MAP).toEqual({
      send_message: ['WRITE_DATA'],
      fetch_inbox: ['READ_DATA'],
      read_message: ['READ_DATA'],
      broadcast: ['WRITE_DATA'],
      list_agents: ['READ_DATA'],
    });
  });
});

describe('requiredBits (default map)', () => {
  const map = loadCapabilityMap({});

  it('maps send_message to WRITE_DATA (bit 1)', () => {
    const bits = requiredBits(map, ['send_message']);
    expect(bits & WRITE_DATA).toBe(WRITE_DATA);
    expect(bits).toBe(WRITE_DATA);
  });

  it('maps fetch_inbox to READ_DATA (bit 0)', () => {
    const bits = requiredBits(map, ['fetch_inbox']);
    expect(bits & READ_DATA).toBe(READ_DATA);
    expect(bits).toBe(READ_DATA);
  });

  it('unions bits across multiple capabilities', () => {
    const bits = requiredBits(map, ['send_message', 'fetch_inbox']);
    expect(bits & READ_DATA).toBe(READ_DATA);
    expect(bits & WRITE_DATA).toBe(WRITE_DATA);
    expect(bits).toBe(READ_DATA | WRITE_DATA);
  });

  it('returns 0n for an empty capability list', () => {
    expect(requiredBits(map, [])).toBe(0n);
  });
});

describe('loadCapabilityMap (--capability-map override)', () => {
  it('adds a new custom capability from the file', async () => {
    const file = await writeMapFile(
      JSON.stringify({ custom_tool: ['ACCESS_PII'] })
    );
    const map = loadCapabilityMap({ file });
    const bits = requiredBits(map, ['custom_tool']);
    expect(bits & ACCESS_PII).toBe(ACCESS_PII);
    expect(bits).toBe(ACCESS_PII);
    // defaults remain intact alongside the extension
    expect(requiredBits(map, ['send_message'])).toBe(WRITE_DATA);
  });

  it('overrides a default capability mapping', async () => {
    const file = await writeMapFile(
      JSON.stringify({ send_message: ['READ_DATA'] })
    );
    const map = loadCapabilityMap({ file });
    const bits = requiredBits(map, ['send_message']);
    expect(bits).toBe(READ_DATA);
    expect(bits & WRITE_DATA).toBe(0n);
  });
});

describe('fail-closed denials', () => {
  it('denies an unmapped capability with unknown_capability', () => {
    const map = loadCapabilityMap({});
    try {
      requiredBits(map, ['no_such_capability']);
      throw new Error('expected requiredBits to throw');
    } catch (err) {
      expect(isVerifyDenial(err)).toBe(true);
      if (isVerifyDenial(err)) {
        expect(err.code).toBe('unknown_capability');
        expect(err.detail).toEqual({ capability: 'no_such_capability' });
      }
    }
  });

  it('denies a capability map with an invalid permission name via internal_error', async () => {
    const file = await writeMapFile(
      JSON.stringify({ custom_tool: ['NOT_A_PERMISSION'] })
    );
    try {
      loadCapabilityMap({ file });
      throw new Error('expected loadCapabilityMap to throw');
    } catch (err) {
      expect(isVerifyDenial(err)).toBe(true);
      if (isVerifyDenial(err)) {
        expect(err.code).toBe('internal_error');
        expect(err.detail).toEqual({ name: 'NOT_A_PERMISSION' });
      }
    }
  });
});
