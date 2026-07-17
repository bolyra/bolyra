module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.test.ts'],
  transformIgnorePatterns: [
    '/node_modules/(?!@noble/)',
  ],
  moduleNameMapper: {
    '^@bolyra/sdk$': '<rootDir>/../../sdk/src/index.ts',
    '^@bolyra/receipts$': '<rootDir>/../receipts/dist/index.js',
    '^@bolyra/mpp$': '<rootDir>/../mpp-payments/src/index.ts',
  },
  transform: {
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
            '@bolyra/mpp': ['../mpp-payments/src/index.ts'],
          },
        },
      },
    ],
  },
};
