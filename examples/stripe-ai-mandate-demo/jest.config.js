module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.test.ts'],
  transformIgnorePatterns: [
    // @noble packages (via @bolyra/receipts) are ESM-only; let ts-jest
    // transform them so Jest can consume them in CommonJS mode.
    '/node_modules/(?!@noble/)',
  ],
  transform: {
    'node_modules/@noble/.+\\.js$': [
      'ts-jest',
      {
        diagnostics: false,
        tsconfig: {
          // Transpile-only: the language-service path chokes on the symlinked
          // file: workspace deps (their sources resolve outside rootDir).
          isolatedModules: true,
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
          isolatedModules: true,
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
