import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';

await build({
  absWorkingDir: fileURLToPath(new URL('.', import.meta.url)),
  entryPoints: { console: 'main.jsx' },
  outdir: '../internal/chatweb/assets/control/ui',
  bundle: true,
  minify: true,
  format: 'esm',
  jsx: 'automatic',
  charset: 'utf8',
  legalComments: 'eof',
  target: 'es2022',
  loader: { '.woff2': 'file', '.svg': 'file' },
  assetNames: 'asset-[hash]',
  publicPath: '/ui',
  external: ['/app.js'],
  define: { 'process.env.NODE_ENV': '"production"' },
});
