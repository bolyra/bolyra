module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.test.ts'],
  moduleNameMapper: {
    '^@bolyra/sdk$': '<rootDir>/../../sdk/src/index.ts',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        // Disable type-checking diagnostics: the e2e test imports @bolyra/sdk
        // source which pulls in circomlibjs (no @types). Type correctness is
        // validated by the SDK's own tsconfig; here we only need transpilation.
        diagnostics: false,
        tsconfig: {
          rootDir: '.',
          outDir: './dist',
          strict: true,
          esModuleInterop: true,
          skipLibCheck: true,
          target: 'ES2020',
          module: 'commonjs',
          lib: ['ES2020'],
          resolveJsonModule: true,
          baseUrl: '.',
          paths: {
            '@bolyra/sdk': ['../../sdk/src/index.ts'],
          },
        },
      },
    ],
  },
};
