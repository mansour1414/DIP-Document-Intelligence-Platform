// Walk the child's runtime import graph and report every package it needs.
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';

const entry = 'src/lib/pdf/form-worker-child.ts';
const seen = new Set();
const packages = new Set();
const files = [];

function resolveSpecifier(spec, fromFile) {
  if (spec.startsWith('node:')) return null;
  if (spec.startsWith('@/')) {
    const base = join('src', spec.slice(2));
    for (const c of [base + '.ts', base + '.tsx', join(base, 'index.ts')]) if (existsSync(c)) return c;
    return null;
  }
  if (spec.startsWith('.')) {
    const base = join(dirname(fromFile), spec);
    for (const c of [base + '.ts', base + '.tsx', join(base, 'index.ts')]) if (existsSync(c)) return c;
    return null;
  }
  // bare package
  const name = spec.startsWith('@') ? spec.split('/').slice(0,2).join('/') : spec.split('/')[0];
  packages.add(name);
  return null;
}

function walk(file) {
  if (seen.has(file)) return;
  seen.add(file);
  files.push(file);
  const src = readFileSync(file, 'utf8');
  // static imports/re-exports
  const specs = [
    ...src.matchAll(/^\s*(?:import|export)\s[^;]*?from\s+["']([^"']+)["']/gmu),
    ...src.matchAll(/^\s*import\s+["']([^"']+)["']/gmu),
    ...src.matchAll(/^\s*(?:import|export)\s+type\s[^;]*?from\s+["']([^"']+)["']/gmu),
    ...src.matchAll(/\bawait\s+import\(\s*["']([^"']+)["']\s*\)/gu),
    ...src.matchAll(/\brequire\(\s*["']([^"']+)["']\s*\)/gu),
  ].map(m => m[1]);
  for (const spec of specs) {
    // type-only imports are erased at runtime, but keep them out of the package list
    const isTypeOnly = new RegExp(`import\\s+type\\s[^;]*?["']${spec.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}["']`, 'u').test(src);
    if (isTypeOnly) continue;
    const dep = resolveSpecifier(spec, file);
    if (dep) walk(dep);
  }
}
walk(entry);
console.log('files in child closure:', files.length);
for (const f of files) console.log('  ', f);
console.log('\nbare packages required:', [...packages].sort().join(', ') || '(none)');
const infra = [...packages].filter(p => /^(ioredis|bullmq|@prisma|@aws-sdk|redis)/.test(p));
console.log('infrastructure packages:', infra.length ? infra.join(', ') : '(NONE)');
