import { access, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { PDFDocument, StandardFonts } from "pdf-lib";

const EXPECTED_DEBIAN = "11.3.0-1+deb12u1"; const directory = await mkdtemp("/tmp/dip/qpdf-gate-");
async function run(args, accepted = [0]) {
  const file = join(directory, `args-${crypto.randomUUID()}`); await writeFile(file, `${args.join("\n")}\n`, { mode: 0o600 }); const mode = (await stat(file)).mode & 0o777; if (mode !== 0o600) throw new Error("argument file permissions are not 0600");
  const result = spawnSync("qpdf", [`@${file}`], { cwd: directory, shell: false, encoding: "utf8", maxBuffer: 1024 * 1024 }); await rm(file, { force: true }); if (!accepted.includes(result.status ?? -1)) throw new Error(`qpdf gate command failed with status ${result.status}`); return result;
}
try {
  if (process.getuid?.() !== 10001 || process.getgid?.() !== 10001) throw new Error("qpdf gate is not running as production uid/gid 10001");
  try { await writeFile("/dip-root-write-probe", "denied"); throw new Error("root filesystem is writable"); } catch (error) { if (error?.code !== "EROFS") throw error; }
  const mounts = await readFile("/proc/mounts", "utf8"); if (!mounts.split("\n").some((line) => line.includes(" / ") && line.split(" ")[3]?.split(",").includes("ro"))) throw new Error("root filesystem is not mounted read-only");
  if (!mounts.match(/\s\/tmp\s+tmpfs\s+[^\n]*size=65536k/) || !mounts.match(/\s\/tmp\/dip\s+tmpfs\s+[^\n]*size=262144k/)) throw new Error("bounded production tmpfs mounts are not present");
  for (const path of ["/usr/bin/gs", "/usr/local/bin/gs"]) { try { await access(path); throw new Error("Ghostscript is present"); } catch (error) { if (error?.code !== "ENOENT") throw error; } }
  const version = spawnSync("qpdf", ["--version"], { shell: false, encoding: "utf8" }); if (version.status !== 0 || !version.stdout.startsWith("qpdf version 11.3.0")) throw new Error("unexpected qpdf executable version");
  const debian = spawnSync("dpkg-query", ["-W", "-f=${Version}", "qpdf"], { shell: false, encoding: "utf8" }); if (debian.status !== 0 || debian.stdout !== EXPECTED_DEBIAN) throw new Error("unexpected qpdf Debian package version");

  const pdf = await PDFDocument.create(); const font = await pdf.embedFont(StandardFonts.Helvetica); const page = pdf.addPage([320, 240]); page.drawText("DIP qpdf production gate", { x: 24, y: 180, font }); const plain = join(directory, "plain.pdf"); await writeFile(plain, await pdf.save({ useObjectStreams: false }), { mode: 0o600 });
  const protectedPdf = join(directory, "protected.pdf"); const decrypted = join(directory, "decrypted.pdf"); const unicodeDecrypted = join(directory, "unicode-decrypted.pdf");
  const userPassword = "gate-user-42"; const ownerPassword = "gate-owner-84"; const unicodePassword = "كلمة-مرور-آمنة-٤٢";
  await run([plain, "--password-mode=unicode", "--encrypt", userPassword, ownerPassword, "256", "--", protectedPdf]);
  const encryption = await run([protectedPdf, "--password-mode=unicode", "--suppress-password-recovery", `--password=${ownerPassword}`, "--show-encryption"]); if (!/R\s*=\s*6/u.test(encryption.stdout) || !/AESv3/u.test(encryption.stdout)) throw new Error("AES-256/R6 was not proven");
  await run([protectedPdf, "--password-mode=unicode", "--suppress-password-recovery", `--password=${userPassword}`, "--decrypt", decrypted]); await PDFDocument.load(await readFile(decrypted));
  const wrong = await run([protectedPdf, "--suppress-password-recovery", "--password=definitely-wrong", "--decrypt", join(directory, "wrong.pdf")], [2]); if (wrong.status !== 2) throw new Error("wrong password did not fail safely");
  const unicodeProtected = join(directory, "unicode.pdf"); await run([plain, "--password-mode=unicode", "--encrypt", unicodePassword, unicodePassword, "256", "--", unicodeProtected]); await run([unicodeProtected, "--password-mode=unicode", "--suppress-password-recovery", `--password=${unicodePassword}`, "--decrypt", unicodeDecrypted]); await PDFDocument.load(await readFile(unicodeDecrypted));

  const permissionPdf = join(directory, "permissions.pdf"); await run([plain, "--password-mode=unicode", "--encrypt", "", ownerPassword, "256", "--print=low", "--extract=n", "--assemble=n", "--form=n", "--annotate=n", "--accessibility=y", "--modify-other=n", "--", permissionPdf]);
  const permissions = (await run([permissionPdf, "--password-mode=unicode", "--suppress-password-recovery", `--password=${ownerPassword}`, "--show-encryption"])).stdout.toLowerCase();
  for (const proof of ["extract for accessibility: allowed", "extract for any purpose: not allowed", "print low resolution: allowed", "print high resolution: not allowed", "modify annotations: not allowed", "modify forms: not allowed", "modify document assembly: not allowed", "modify other: not allowed"]) if (!permissions.includes(proof)) throw new Error(`permission proof missing: ${proof}`);

  const malformed = join(directory, "malformed-xref.pdf"); const repaired = join(directory, "repaired.pdf"); const plainBytes = Buffer.from(await readFile(plain)); const broken = Buffer.from(plainBytes.toString("latin1").replace(/startxref\s+\d+/u, "startxref\n0"), "latin1"); await writeFile(malformed, broken, { mode: 0o600 });
  await run([malformed, repaired], [0, 3]); await run([repaired, "--check"], [0, 3]); await PDFDocument.load(await readFile(repaired));
  const corrupt = join(directory, "corrupt.pdf"); await writeFile(corrupt, Buffer.from("%PDF-1.7\ntruncated"), { mode: 0o600 }); const rejected = await run([corrupt, join(directory, "bad-output.pdf")], [2]); if (rejected.status !== 2) throw new Error("unrecoverable input was not rejected");

  const packages = spawnSync("dpkg-query", ["-W", "-f=${Package}\t${Version}\t${source:Package}\n"], { shell: false, encoding: "utf8" }); if (packages.status !== 0) throw new Error("worker package inventory failed");
  const copyright = await readFile("/usr/share/doc/qpdf/copyright", "utf8"); if (!/Apache License(?:,? Version)? 2\.0|Apache-2\.0/iu.test(copyright)) throw new Error("qpdf Apache-2.0 license proof is missing");
  const inventory = packages.stdout.trim().split("\n").map((line) => { const [name, versionValue, source] = line.split("\t"); return { name, version: versionValue, source }; });
  const sbom = { spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", name: "dip-production-worker-debian-packages", documentNamespace: `https://dip.local/sbom/qpdf-worker/${crypto.randomUUID()}`, creationInfo: { created: new Date().toISOString(), creators: ["Tool: DIP qpdf production gate"] }, packages: inventory.map((item, index) => ({ SPDXID: `SPDXRef-Package-${index + 1}`, name: item.name, versionInfo: item.version, supplier: "Organization: Debian", downloadLocation: "NOASSERTION", filesAnalyzed: false, licenseConcluded: ["qpdf", "libqpdf29"].includes(item.name) ? "Apache-2.0" : "NOASSERTION", licenseDeclared: ["qpdf", "libqpdf29"].includes(item.name) ? "Apache-2.0" : "NOASSERTION", externalRefs: item.source ? [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: `pkg:deb/debian/${encodeURIComponent(item.name)}@${encodeURIComponent(item.version)}?source=${encodeURIComponent(item.source)}` }] : [] })) };
  if (process.env.QPDF_SBOM_PATH) await writeFile(process.env.QPDF_SBOM_PATH, `${JSON.stringify(sbom, null, 2)}\n`, { mode: 0o644 });
  console.log(JSON.stringify({ gate: "qpdf-production-security-v1", qpdfVersion: "11.3.0", debianVersion: EXPECTED_DEBIAN, qpdfLicense: "Apache-2.0", aes256: true, correctPassword: true, wrongPasswordRejected: true, unicodePassword: true, permissions: true, repairRecoverable: true, repairUnrecoverableRejected: true, uid: 10001, readOnlyRoot: true, boundedTmpfs: true, ghostscriptAbsent: true, sbomPackages: inventory.length }));
} finally { await rm(directory, { recursive: true, force: true }); }
