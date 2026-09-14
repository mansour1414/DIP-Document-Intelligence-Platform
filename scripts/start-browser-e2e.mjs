import { cpSync, existsSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";

const projectRoot = process.cwd();
const localEnv = path.join(projectRoot, ".env.local");
if (existsSync(localEnv)) process.loadEnvFile(localEnv);
const standaloneRoot = path.join(projectRoot, ".next", "standalone");
const serverPath = path.join(standaloneRoot, "server.js");

if (!existsSync(serverPath)) {
  throw new Error("Standalone Next.js output is missing. Run `npm run build` first.");
}

for (const [source, destination] of [
  [path.join(projectRoot, "public"), path.join(standaloneRoot, "public")],
  [path.join(projectRoot, ".next", "static"), path.join(standaloneRoot, ".next", "static")],
]) {
  if (existsSync(source)) cpSync(source, destination, { recursive: true, force: true });
}

process.chdir(standaloneRoot);
await import(pathToFileURL(serverPath).href);
