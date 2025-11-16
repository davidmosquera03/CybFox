import {
  defineConfig
} from 'vite'
import {
  resolve
} from 'path'
import {
  svelte
} from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  base: '',
  plugins: [svelte()],
  build: {
    outDir: 'dist', 
    emptyOutDir: true,
    modulePreload: false,
    target: 'es2015',
    rollupOptions: {
      input: {
        blocked: resolve(__dirname, 'src/blocked/blocked.html')
      },
      output: {
        entryFileNames: `[name].js`,
        chunkFileNames: `[name].js`,
        assetFileNames: `[name].[ext]`,
        manualChunks: undefined
      }
    }
  }
})
