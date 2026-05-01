import { defineConfig } from 'vite';
import { resolve } from 'path';
import { copyFileSync, mkdirSync, readdirSync, existsSync } from 'fs';

// Vite is just our bundler — we don't use its dev server. The output mirrors
// the structure Manifest V3 expects: background.js, content.js, popup.js,
// popup.html plus the static icons + manifest.
export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        background: resolve(__dirname, 'src/background.ts'),
        content: resolve(__dirname, 'src/content.ts'),
        popup: resolve(__dirname, 'src/popup.ts'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name].js',
        assetFileNames: '[name].[ext]',
      },
    },
    target: 'es2022',
    minify: false, // legible output for code review
    sourcemap: false,
  },
  plugins: [
    {
      name: 'copy-static',
      closeBundle() {
        // Copy public/* and the popup.html into dist/.
        const publicDir = resolve(__dirname, 'public');
        const distDir = resolve(__dirname, 'dist');
        const iconsDir = resolve(__dirname, 'icons');
        const popupHtml = resolve(__dirname, 'src/popup.html');

        if (existsSync(publicDir)) {
          for (const f of readdirSync(publicDir)) {
            copyFileSync(resolve(publicDir, f), resolve(distDir, f));
          }
        }
        if (existsSync(iconsDir)) {
          mkdirSync(resolve(distDir, 'icons'), { recursive: true });
          for (const f of readdirSync(iconsDir)) {
            copyFileSync(resolve(iconsDir, f), resolve(distDir, 'icons', f));
          }
        }
        if (existsSync(popupHtml)) {
          copyFileSync(popupHtml, resolve(distDir, 'popup.html'));
        }
      },
    },
  ],
});
