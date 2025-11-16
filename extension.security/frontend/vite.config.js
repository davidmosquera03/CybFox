import {
  defineConfig
} from 'vite'
import {
  svelte
} from '@sveltejs/vite-plugin-svelte'
import {
  resolve
} from 'path'


export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: '../dist', // compilamos directo a extension.security/dist
    emptyOutDir: false, // no borra todo lo que ya tengas
    rollupOptions: {
      input: {
        blocked: resolve(__dirname, 'src/blocked.html'),
        popup: resolve(__dirname, 'src/popup.html')
      }
    }
  }
})