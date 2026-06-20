import { main } from '../src/main';

// Capture console output
function captureConsole() {
  const logs: string[] = [];
  const errors: string[] = [];
  const origLog = console.log;
  const origError = console.error;

  console.log = (...args: unknown[]) => logs.push(args.map(String).join(' '));
  console.error = (...args: unknown[]) => errors.push(args.map(String).join(' '));

  return {
    logs,
    errors,
    restore() {
      console.log = origLog;
      console.error = origError;
    },
  };
}

describe('CLI routing', () => {
  afterEach(() => {
    process.exitCode = undefined;
  });

  it('shows help with no args', async () => {
    const cap = captureConsole();
    try {
      await main([]);
      expect(cap.logs.join('\n')).toContain('Bolyra CLI');
    } finally {
      cap.restore();
    }
  });

  it('shows help with --help', async () => {
    const cap = captureConsole();
    try {
      await main(['--help']);
      expect(cap.logs.join('\n')).toContain('Bolyra CLI');
    } finally {
      cap.restore();
    }
  });

  it('shows version with --version', async () => {
    const cap = captureConsole();
    try {
      await main(['--version']);
      expect(cap.logs.join('\n')).toContain('@bolyra/cli');
    } finally {
      cap.restore();
    }
  });

  it('sets exit code 2 for unknown command', async () => {
    const cap = captureConsole();
    try {
      await main(['nonexistent']);
      expect(process.exitCode).toBe(2);
    } finally {
      cap.restore();
    }
  });

  it('sets exit code 2 for unknown cred subcommand', async () => {
    const cap = captureConsole();
    try {
      await main(['cred', 'unknown']);
      expect(process.exitCode).toBe(2);
    } finally {
      cap.restore();
    }
  });

  it('sets exit code 2 for unknown key subcommand', async () => {
    const cap = captureConsole();
    try {
      await main(['key', 'unknown']);
      expect(process.exitCode).toBe(2);
    } finally {
      cap.restore();
    }
  });

  it('sets exit code 2 for unknown receipt subcommand', async () => {
    const cap = captureConsole();
    try {
      await main(['receipt', 'unknown']);
      expect(process.exitCode).toBe(2);
    } finally {
      cap.restore();
    }
  });
});

describe('cred list with empty store', () => {
  it('shows empty message', async () => {
    const cap = captureConsole();
    try {
      // cred list with default store will show empty or existing creds
      await main(['cred', 'list', '--json']);
      // Should not throw
    } finally {
      cap.restore();
    }
  });
});

describe('cred create validation', () => {
  afterEach(() => {
    process.exitCode = undefined;
  });

  it('requires --operator-key', async () => {
    const cap = captureConsole();
    try {
      await main(['cred', 'create', '--model', 'test', '--permissions', 'read', '--expiry', '30d']);
      expect(process.exitCode).toBe(2);
      expect(cap.errors.join('\n')).toContain('--operator-key is required');
    } finally {
      cap.restore();
    }
  });

  it('requires --model', async () => {
    const cap = captureConsole();
    try {
      await main(['cred', 'create', '--operator-key', '/tmp/nope', '--permissions', 'read', '--expiry', '30d']);
      expect(process.exitCode).toBe(2);
      expect(cap.errors.join('\n')).toContain('--model is required');
    } finally {
      cap.restore();
    }
  });

  it('requires --permissions', async () => {
    const cap = captureConsole();
    try {
      await main(['cred', 'create', '--operator-key', '/tmp/nope', '--model', 'test', '--expiry', '30d']);
      expect(process.exitCode).toBe(2);
      expect(cap.errors.join('\n')).toContain('--permissions is required');
    } finally {
      cap.restore();
    }
  });

  it('requires --expiry', async () => {
    const cap = captureConsole();
    try {
      await main(['cred', 'create', '--operator-key', '/tmp/nope', '--model', 'test', '--permissions', 'read']);
      expect(process.exitCode).toBe(2);
      expect(cap.errors.join('\n')).toContain('--expiry is required');
    } finally {
      cap.restore();
    }
  });
});

describe('cred inspect validation', () => {
  afterEach(() => {
    process.exitCode = undefined;
  });

  it('requires an argument', async () => {
    const cap = captureConsole();
    try {
      await main(['cred', 'inspect']);
      expect(process.exitCode).toBe(2);
    } finally {
      cap.restore();
    }
  });
});

describe('cred revoke validation', () => {
  afterEach(() => {
    process.exitCode = undefined;
  });

  it('requires a commitment argument', async () => {
    const cap = captureConsole();
    try {
      await main(['cred', 'revoke']);
      expect(process.exitCode).toBe(2);
    } finally {
      cap.restore();
    }
  });
});

describe('key show validation', () => {
  afterEach(() => {
    process.exitCode = undefined;
  });

  it('requires a file argument', async () => {
    const cap = captureConsole();
    try {
      await main(['key', 'show']);
      expect(process.exitCode).toBe(2);
    } finally {
      cap.restore();
    }
  });

  it('errors on missing file', async () => {
    const cap = captureConsole();
    try {
      await main(['key', 'show', '/tmp/nonexistent-key-file']);
      expect(process.exitCode).toBe(1);
    } finally {
      cap.restore();
    }
  });
});

describe('receipt verify validation', () => {
  afterEach(() => {
    process.exitCode = undefined;
  });

  it('requires a file argument or --stdin', async () => {
    const cap = captureConsole();
    try {
      await main(['receipt', 'verify']);
      expect(process.exitCode).toBe(2);
    } finally {
      cap.restore();
    }
  });
});
