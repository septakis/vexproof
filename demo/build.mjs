import * as esbuild from 'esbuild';
import { writeFileSync } from 'node:fs';
const r = await esbuild.build({ entryPoints: ['src/main.jsx'], bundle: true, minify: true, outfile: 'dist/app.js', metafile: true, format: 'esm', define: { 'process.env.NODE_ENV': '"production"' }, jsx: 'automatic', logLevel: 'error' });
writeFileSync('dist/meta.json', JSON.stringify(r.metafile));
