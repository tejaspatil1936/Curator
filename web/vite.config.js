import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    // All interfaces inside the container; compose publishes it on 127.0.0.1 only.
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
  },
})
