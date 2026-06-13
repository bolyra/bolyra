module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.test.ts'],
  transformIgnorePatterns: [
    // @noble packages are ESM-only; let ts-jest transform them so Jest can
    // consume them in CommonJS mode. The pattern must match node_modules in
    // both this package and sibling packages (e.g., ../receipts/node_modules/).
    '/node_modules/(?!@noble/)',
  ],
  moduleNameMapper: {
    '^@bolyra/sdk$': '<rootDir>/../../sdk/src/index.ts',
    '^@bolyra/receipts$': '<rootDir>/../receipts/dist/index.js',
  },
  transform: {
    // Transform ESM-only @noble packages to CJS so Jest can consume them.
    'node_modules/@noble/.+\\.js$': [
      'ts-jest',
      {
        diagnostics: false,
        tsconfig: {
          allowJs: true,
          esModuleInterop: true,
          target: 'ES2020',
          module: 'commonjs',
        },
      },
    ],
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
            '@bolyra/receipts': ['../receipts/dist/index.js'],
          },
        },
      },
    ],
  },
};
