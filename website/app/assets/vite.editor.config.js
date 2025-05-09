import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: 'src',
  base: '/static/',
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/js/editor.js'),
      name: 'Editor',
      fileName: () => 'editor.js',
      formats: ['iife']
    },
    outDir: '../static/js',
    emptyOutDir: false,
    treeshake: true,
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true
      },
      mangle: true,
      output: {
        comments: false
      }
    },
  },
});
