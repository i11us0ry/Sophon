import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    extensions: ['.ts', '.tsx', '.vue', '.js', '.json'],
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:18080',
        changeOrigin: true,
      },
      '/mcp': {
        target: 'http://127.0.0.1:18081',
        changeOrigin: true,
      },
    },
  },
})
