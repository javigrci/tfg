import { defineConfig } from 'vitest/config'

// Solo lógica pura de src/lib/ — sin jsdom ni React Testing Library.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
