// Compute the real transitive import closure of the child entry, resolved the same
// way the child resolves it at runtime (tsx + the "@/..." alias).
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
const seen = new Set();
function resolveSpec(spec, from) {
  if (spec.startsWith("@/")) return resolve("src", spec.slice(2));
  if (spec.startsWith(".")) return resolve(dirname(from), spec);
  return null;
}
function walk(file) {
  if (seen.has(file)) return;
  seen.add(file);
  let src;
  try { src = readFileSync(file, "utf8"); } catch { return; }
  for (const m of src.matchAll(/from\s+"([^"]+)"/g)) {
    const target = resolveSpec(m[1], file);
    if (!target) continue;
    for (const ext of [".ts", ".tsx", "/index.ts"]) {
      try { readFileSync(target + ext); walk(target + ext); break; } catch {}
    }
  }
}
walk(resolve("src/lib/pdf/form-worker-child.ts"));
console.log([...seen].sort().join("\n"));
console.log("--- count:", seen.size);
