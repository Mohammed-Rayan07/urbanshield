import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // The backend runs on :8000; proxying keeps the browser on one origin (no CORS in dev).
    // 127.0.0.1, not localhost: Node may resolve localhost to ::1 while uvicorn binds IPv4 only.
    proxy: { '/api': 'http://127.0.0.1:8000' },
  },
})
