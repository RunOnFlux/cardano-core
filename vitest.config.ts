import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // The 10,000-case oracle sweep (`yarn oracle`) derives thousands of keys per test.
    testTimeout: process.env['CARDANO_ORACLE_CASES'] ? 3_600_000 : 60_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text-summary', 'text'],
    },
  },
});
