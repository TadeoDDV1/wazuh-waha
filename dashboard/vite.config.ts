import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Proxy en dev: el browser habla SIEMPRE mismo origen con el relay
  // (requisito de la cookie de sesión BFF). El destino real del relay es
  // VITE_API_URL (p. ej. http://10.33.25.154:8765) o localhost:8765.
  const root = fileURLToPath(new URL('.', import.meta.url))
  const env = loadEnv(mode, root, '')
  const relayTarget = env.VITE_API_URL || 'http://localhost:8765'

  return {
    plugins: [react()],
    build: {
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes('node_modules')) {
              if (id.includes('react') || id.includes('react-dom')) {
                return 'vendor-react'
              }
              if (id.includes('lucide-react')) {
                return 'vendor-lucide'
              }
              if (id.includes('axios') || id.includes('sonner')) {
                return 'vendor-core'
              }
              return 'vendor-libs'
            }
          },
        },
      },
      chunkSizeWarningLimit: 600,
    },
    server: {
      proxy: {
        '/api': { target: relayTarget, changeOrigin: false },
        '/debug': { target: relayTarget, changeOrigin: false },
        '/health': { target: relayTarget, changeOrigin: false },
      },
    },
  }
})
