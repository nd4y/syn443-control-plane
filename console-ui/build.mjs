import { build } from 'esbuild';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const noticeFiles = [
  'RED-HAT-FONT-LICENSE',
  'node_modules/@patternfly/react-core/LICENSE',
  'node_modules/@patternfly/react-icons/LICENSE',
  'node_modules/@patternfly/react-styles/LICENSE',
  'node_modules/@patternfly/react-tokens/LICENSE',
];
const notices = await Promise.all(
  noticeFiles.map((name) => readFile(new URL(name, import.meta.url), 'utf8')),
);

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
  footer: {
    css:
      '/*! Third-party notices\n' +
      notices.join('\n\n').replaceAll('*/', '* /') +
      '\n*/',
  },
  target: 'es2022',
  loader: { '.woff2': 'file', '.svg': 'file' },
  assetNames: 'asset-[hash]',
  publicPath: '/ui',
  external: ['/app.js'],
  define: { 'process.env.NODE_ENV': '"production"' },
});
