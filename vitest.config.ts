import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    testTimeout: 15000,
    hookTimeout: 10000,
    include: ['packages/*/src/**/*.test.ts'],
  },
});
