import { defineConfig } from 'vite';
import { viteStaticCopy } from 'vite-plugin-static-copy';
import path from 'path';


export default defineConfig({
  root: 'src',
  build: {
    outDir: '../static',
    emptyOutDir: false, // Preserve existing directories
    assetsDir: '', // Avoid default assets folder
    rollupOptions: {
      input: {
        style: path.resolve(__dirname, 'src/css/core.css'),
      },
      output: {
        assetFileNames: ({ name }) => {
          if (/\.css$/.test(name)) return `css/[name][extname]`;
          if (/\.(woff|woff2|ttf|eot)$/.test(name)) return 'fonts/[name][extname]';
          if (/\.(png|jpg|jpeg|svg|gif)$/.test(name)) return 'images/[name][extname]';
          return '[name][extname]';
        },
      },
    },
    minify: 'esbuild',
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
      '@js': path.resolve(__dirname, 'src/js'),
      '@css': path.resolve(__dirname, 'src/css'),
      '@fonts': path.resolve(__dirname, 'src/fonts'),
    },
  },
  plugins: [
    viteStaticCopy({
      targets: [
        // JavaScript
        {
          src: path.resolve(__dirname, 'node_modules/bootstrap/dist/js/bootstrap.min.js'),
          dest: 'js/vendor',
        },
        {
          src: path.resolve(__dirname, 'node_modules/jquery/dist/jquery.min.js'),
          dest: 'js/vendor',
        },
        {
          src: path.resolve(__dirname, 'node_modules/jquery-ui/dist/jquery-ui.min.js'),
          dest: 'js/vendor',
        },
        {
          src: path.resolve(__dirname, 'node_modules/select2/dist/js/select2.min.js'),
          dest: 'js/vendor',
        },
        {
          src: path.resolve(__dirname, 'node_modules/zxcvbn/dist/zxcvbn.js'),
          dest: 'js/vendor',
        },
        {
          src: path.resolve(__dirname, 'node_modules/vue/dist/vue.global.js'),
          dest: 'js/vendor',
        },
        {
          src: path.resolve(__dirname, 'node_modules/@popperjs/core/dist/umd/popper.min.js'),
          dest: 'js/vendor',
        },
        // Day.js
        {
          src: path.resolve(__dirname, 'node_modules/dayjs/dayjs.min.js'),
          dest: 'js/vendor/dayjs',
        },
        {
          src: path.resolve(__dirname, 'node_modules/dayjs/plugin/utc.js'),
          dest: 'js/vendor/dayjs',
          rename: 'dayjs-utc.js',
        },
        {
          src: path.resolve(__dirname, 'node_modules/dayjs/plugin/relativeTime.js'),
          dest: 'js/vendor/dayjs',
          rename: 'dayjs-relativeTime.js',
        },
        // CSS
        {
          src: path.resolve(__dirname, 'node_modules/bootstrap/dist/css/bootstrap.min.css'),
          dest: 'css/vendor/',
        },
        {
          src: path.resolve(__dirname, 'node_modules/jquery-ui/dist/themes/base/jquery-ui.min.css'),
          dest: 'css/vendor/',
        },
        {
          src: path.resolve(__dirname, 'node_modules/select2/dist/css/select2.min.css'),
          dest: 'css/vendor/',
        },
        {
          src: path.resolve(__dirname, 'node_modules/select2-bootstrap-5-theme/dist/select2-bootstrap-5-theme.min.css'),
          dest: 'css/vendor/',
        },
        // FontAwesome CSS with URL transformation
        {
          src: path.resolve(__dirname, 'node_modules/@fortawesome/fontawesome-free/css/fontawesome.css'),
          dest: 'css/vendor',
          transform: (content) => {
            return content.replace(
              /url\(['"]?\.\.\/webfonts\/([^'"]+)['"]?\)/g,
              `url('../../fonts/vendor/$1')`
            );
          },
        },
        {
          src: path.resolve(__dirname, 'node_modules/@fortawesome/fontawesome-free/css/brands.css'),
          dest: 'css/vendor',
          transform: (content) => {
            return content.replace(
              /url\(['"]?\.\.\/webfonts\/([^'"]+)['"]?\)/g,
              `url('../../fonts/vendor/$1')`
            );
          },
        },
        {
          src: path.resolve(__dirname, 'node_modules/@fortawesome/fontawesome-free/css/solid.css'),
          dest: 'css/vendor',
          transform: (content) => {
            return content.replace(
              /url\(['"]?\.\.\/webfonts\/([^'"]+)['"]?\)/g,
              `url('../../fonts/vendor/$1')`
            );
          },
        },
        // FontAwesome Fonts
        {
          src: path.resolve(__dirname, 'node_modules/@fortawesome/fontawesome-free/webfonts/fa-{brands,solid}-*.{ttf,woff2}'),
          dest: 'fonts/vendor',
        },
      ],
    }),
  ],
});
