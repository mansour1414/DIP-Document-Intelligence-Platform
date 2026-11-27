/**
 * Start the standalone server for the Release B E2E job.
 *
 * ## Why this relocates (R6.4)
 *
 * The standalone output lives at `.next/standalone`, which is *inside* this checkout. Node
 * resolves a bare specifier by walking parent directories, so a server started in place
 * can satisfy a missing package from the repository's own `node_modules`. That is fine for
 * a dev server and wrong for this job: the point of the job is to exercise the artifact
 * that ships, and an artifact that needs the checkout's dependencies is not the artifact
 * that ships.
 *
 * So the tree is copied — together with the static assets Next does not place there — to a
 * temporary directory outside any checkout, and the server is started from that copy. The
 * copy is removed on exit. Nothing is installed and nothing is repaired: if the copy cannot
 * start, that is the finding.
 *
 * The worker-image build has no equivalent step because `/app` is already the image root
 * and is not nested inside a repository.
 */
import { cpSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import path from "node:path";

const projectRoot = process.cwd();
const localEnv = path.join(projectRoot, ".env.local");
if (existsSync(localEnv)) process.loadEnvFile(localEnv);

const standaloneSource = path.join(projectRoot, ".next", "standalone");
const sourceServer = path.join(standaloneSource, "server.js");
if (!existsSync(sourceServer)) {
  throw new Error("Standalone Next.js output is missing. Run `npm run build` first.");
}

// Relocated *outside* the repository so no ancestor directory can supply a dependency.
const artifactRoot = mkdtempSync(path.join(tmpdir(), "dip-standalone-"));
cpSync(standaloneSource, artifactRoot, { recursive: true, verbatimSymlinks: true, dereference: false });

// The established packaging procedure: `next build` writes static assets and `public/` beside
// the server output rather than inside the traced tree, and the standalone server expects
// them at its own root. This is packaging, not repair — the same two copies any standalone
// deployment performs.
for (const [source, destination] of [
  [path.join(projectRoot, "public"), path.join(artifactRoot, "public")],
  [path.join(projectRoot, ".next", "static"), path.join(artifactRoot, ".next", "static")],
]) {
  if (existsSync(source)) cpSync(source, destination, { recursive: true, force: true });
}

const cleanup = () => rmSync(artifactRoot, { recursive: true, force: true });
for (const signal of ["SIGTERM", "SIGINT"]) process.on(signal, () => { cleanup(); process.exit(0); });
process.on("exit", cleanup);

console.log(`Standalone server: ${path.join(artifactRoot, "server.js")} (relocated from ${standaloneSource})`);
process.chdir(artifactRoot);
await import(pathToFileURL(path.join(artifactRoot, "server.js")).href);
