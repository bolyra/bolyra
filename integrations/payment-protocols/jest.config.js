module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.test.ts'],
  moduleNameMapper: {
    '^@bolyra/sdk$': '<rootDir>/../../sdk/src',
  },
  transformIgnorePatterns: [
    'node_modules/(?!(@noble|@bolyra/receipts)/)',
  ],
  transform: {
    '^.+\\.jsx?$': [
      'ts-jest',
      {
        diagnostics: false,
        useESM: false,
        tsconfig: {
          allowJs: true,
          rootDir: '.',
          outDir: './dist',
          strict: true,
          esModuleInterop: true,
          skipLibCheck: true,
          target: 'ES2020',
          module: 'commonjs',
          lib: ['ES2020'],
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
        },
      },
    ],
  },
};
