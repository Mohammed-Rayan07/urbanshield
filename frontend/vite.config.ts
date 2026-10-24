import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // The backend runs on :8000; proxying keeps the browser on one origin (no CORS in dev).
    proxy: { '/api': 'http://localhost:8000' },
  },
})
