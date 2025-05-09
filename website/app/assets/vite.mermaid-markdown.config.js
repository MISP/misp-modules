import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: 'src',
  base: '/static/',
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/js/mermaid-markdown.js'),
      name: 'mermaidMarkdown',
      fileName: () => 'mermaid-markdown.js',
      formats: ['umd'],
    },
    outDir: '../static/js',
    emptyOutDir: false,
    minify: 'esbuild',
    rollupOptions: {
      external: ['markdown-it'],
      output: {
        globals: {
          'markdown-it': 'markdownit',
        },
      },
    },
  },
});
