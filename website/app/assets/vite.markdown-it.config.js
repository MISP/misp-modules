import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: 'src',
  base: '/static/',
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/js/markdown-it.js'),
      name: 'markdownit',
      fileName: () => 'markdown-it.js',
      formats: ['umd']
    },
    outDir: '../static/js',
    emptyOutDir: false,
    minify: 'esbuild',
    rollupOptions: {
      output: {
        globals: {
          'markdown-it': 'markdownit',
          'linkify-it': 'linkifyIt',
          'punycode': 'punycode',
        },
      },
    },
 },
});
