import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { viteSingleFile } from 'vite-plugin-singlefile'

// The built output is inlined into a single index.html so the Avalonia host
// can load it with NativeWebView.NavigateToString() — there is no static file
// server at runtime, so all JS/CSS must be embedded in the document.
export default defineConfig({
  plugins: [vue(), viteSingleFile()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // CSS code-splitting would emit a separate .css file that NavigateToString
    // cannot resolve; inline everything into the single HTML bundle.
    cssCodeSplit: false,
    assetsInlineLimit: 100000000,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
  server: {
    // Hot-reload dev server. In DEBUG builds the host loads http://localhost:5173
    // instead of the bundled document so UI changes apply without a rebuild.
    port: 5173,
    strictPort: true,
  },
})
