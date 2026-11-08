import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The daemon embeds dist/ and serves it at /dashboard/. In development the Vite
// server proxies the admin API and the one-time login route to a running
// daemon. The daemon only accepts its own loopback Host and Origin, so the
// proxy rewrites both. Set PV_DAEMON_URL to point at a non-default port.
const daemon = process.env.PV_DAEMON_URL ?? 'http://127.0.0.1:8787';
const daemonHost = new URL(daemon).host;

const toDaemon = {
  target: daemon,
  changeOrigin: true,
  configure(proxy: { on: (ev: 'proxyReq', fn: (req: { setHeader(k: string, v: string): void }) => void) => void }) {
    proxy.on('proxyReq', (req) => {
      req.setHeader('host', daemonHost);
      req.setHeader('origin', daemon);
    });
  },
};

export default defineConfig({
  base: '/dashboard/',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': toDaemon,
      '/dashboard/login': toDaemon,
    },
  },
});
