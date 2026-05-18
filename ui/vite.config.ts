import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'fs'
import { resolve } from 'path'

const pkg = JSON.parse(readFileSync(resolve(__dirname, 'package.json'), 'utf-8')) as {
  version: string
  dependencies: Record<string, string>
  devDependencies: Record<string, string>
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
  define: {
    __UI_VERSION__: JSON.stringify(pkg.version),
    __UI_BUILD_TIME__: JSON.stringify(new Date().toISOString()),
    __REACT_VERSION__: JSON.stringify((pkg.dependencies['react'] ?? '').replace(/^\^/, '')),
    __VITE_VERSION__: JSON.stringify((pkg.devDependencies['vite'] ?? '').replace(/^\^/, '')),
    __TS_VERSION__: JSON.stringify((pkg.devDependencies['typescript'] ?? '').replace(/^~/, '')),
  },
})
