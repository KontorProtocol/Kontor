import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'
import wasm from 'vite-plugin-wasm'
import path from 'path'


export default defineConfig({
  plugins: [
    wasm(), // Add the WebAssembly plugin first
    react(),
    nodePolyfills({
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
      protocolImports: true,
    }),
  ],
  envDir: path.resolve(__dirname, '../..'),
  optimizeDeps: {
    esbuildOptions: {
      target: 'esnext' // Changed from es2020 to esnext for top-level await support
    }
  },
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    target: 'esnext', // Changed from es2020 to esnext for top-level await support
    rollupOptions: {
      output: {
        manualChunks: {
          // Separate large dependencies into their own chunks
          'bitcoin-lib': ['bitcoinjs-lib'],
          'secp256k1': ['tiny-secp256k1'],
        }
      }
    }
  }
})
