#!/usr/bin/env node

import { lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";

const root = path.resolve(process.argv[2] ?? "/app/node_modules");

function relativePath(value) {
  const relative = path.relative(path.dirname(root), value).split(path.sep).join("/");
  return relative || path.basename(value);
}

function directories(parent) {
  return readdirSync(parent, { withFileTypes: true })
    .filter((entry) => !entry.name.startsWith(".") && (entry.isDirectory() || entry.isSymbolicLink()))
    .map((entry) => path.join(parent, entry.name))
    .sort((left, right) => left.localeCompare(right, "en"));
}

function packageDirectories(nodeModules) {
  const result = [];
  for (const candidate of directories(nodeModules)) {
    if (path.basename(candidate).startsWith("@")) {
      for (const scoped of directories(candidate)) result.push(scoped);
    } else {
      result.push(candidate);
    }
  }
  return result;
}

function inspectPackage(packageDir) {
  const manifestPath = path.join(packageDir, "package.json");
  const record = {
    path: relativePath(packageDir),
    status: "COMPLETE",
    name: null,
    version: null,
    license: "NOASSERTION",
    missing_fields: [],
    diagnostic: null,
  };
  try {
    const stat = lstatSync(manifestPath);
    if (!stat.isFile() && !stat.isSymbolicLink()) throw new Error("package.json is not a regular file");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (typeof manifest.name === "string" && manifest.name.trim()) record.name = manifest.name;
    else record.missing_fields.push("name");
    if (typeof manifest.version === "string" && manifest.version.trim()) record.version = manifest.version;
    else record.missing_fields.push("version");
    if (typeof manifest.license === "string" && manifest.license.trim()) record.license = manifest.license;
    else if (Array.isArray(manifest.licenses) && manifest.licenses.length) record.license = "SEE_LICENSES_FIELD";
  } catch (error) {
    record.missing_fields.push("package.json");
    record.diagnostic = error instanceof SyntaxError ? "INVALID_PACKAGE_JSON" : "MISSING_OR_UNREADABLE_PACKAGE_JSON";
  }
  if (record.missing_fields.length) record.status = "MISSING_METADATA";
  return record;
}

function collect(nodeModules, records = [], visited = new Set()) {
  const resolved = path.resolve(nodeModules);
  if (visited.has(resolved)) return records;
  visited.add(resolved);
  for (const packageDir of packageDirectories(resolved)) {
    records.push(inspectPackage(packageDir));
    const nested = path.join(packageDir, "node_modules");
    try {
      if (lstatSync(nested).isDirectory()) collect(nested, records, visited);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  return records;
}

const records = collect(root).sort((left, right) =>
  left.path.localeCompare(right.path, "en") || (left.name ?? "").localeCompare(right.name ?? "", "en")
);
process.stdout.write(`${JSON.stringify(records, null, 2)}\n`);
