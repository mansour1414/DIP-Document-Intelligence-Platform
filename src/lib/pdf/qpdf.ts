import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { PDFDocument } from "pdf-lib";
import { runtimeLimits } from "@/lib/runtime/config";
import type { Phase1SecretPayload } from "@/lib/secrets/phase1";

export const APPROVED_QPDF_VERSION = "11.3.0";
type QpdfTool = "protect-pdf" | "unlock-pdf" | "pdf-permissions" | "repair-pdf";
type PermissionOptions = { printing: "none" | "low" | "full"; extraction: boolean; assembly: boolean; forms: boolean; annotations: boolean };
export class QpdfError extends Error { constructor(public readonly code: string, message: string) { super(message); } }

async function execute(args: string[], cwd: string, accepted = [0], maxStdoutLines?: number) {
  const argumentFile = join(cwd, `qpdf-${crypto.randomUUID()}.args`); await writeFile(argumentFile, `${args.join("\n")}\n`, { mode: 0o600 });
  try {
    const result = await new Promise<{ code: number; stdout: string; stdoutLines: number }>((resolve, reject) => {
      const child = spawn(process.env.QPDF_PATH ?? "qpdf", [`@${argumentFile}`], { cwd, shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = ""; let stdoutLines = 0; let timedOut = false; let limitExceeded = false; child.stdout.setEncoding("utf8"); child.stdout.on("data", (chunk: string) => { stdoutLines += (chunk.match(/\n/gu) ?? []).length; if (stdout.length < 16_384) stdout += chunk; if (maxStdoutLines !== undefined && stdoutLines > maxStdoutLines && !limitExceeded) { limitExceeded = true; child.kill("SIGTERM"); } }); child.stderr.resume();
      const timer = setTimeout(() => { timedOut = true; child.kill("SIGTERM"); setTimeout(() => child.kill("SIGKILL"), 2_000).unref(); }, runtimeLimits.jobTimeoutMs); timer.unref?.();
      child.once("error", (error) => { clearTimeout(timer); reject(error); }); child.once("close", (code) => { clearTimeout(timer); if (timedOut) reject(new QpdfError("PROCESSING_TIMEOUT", "qpdf exceeded the configured processing time limit.")); else if (limitExceeded) reject(new QpdfError("PDF_OBJECT_LIMIT_EXCEEDED", "The PDF exceeds the configured object limit.")); else resolve({ code: code ?? -1, stdout, stdoutLines }); });
    });
    if (!accepted.includes(result.code)) throw new QpdfError("QPDF_PROCESSING_FAILED", "qpdf rejected the document or credentials.");
    return result;
  } finally { await rm(argumentFile, { force: true }); }
}

async function reopen(bytes: Uint8Array, expectedPages?: number) {
  const pdf = await PDFDocument.load(bytes, { ignoreEncryption: false }).catch(() => { throw new QpdfError("OUTPUT_VALIDATION_FAILED", "The generated PDF could not be reopened."); });
  if (!pdf.getPageCount() || pdf.getPageCount() > runtimeLimits.maxPages || (expectedPages !== undefined && pdf.getPageCount() !== expectedPages)) throw new QpdfError("OUTPUT_VALIDATION_FAILED", "The generated PDF page count is invalid.");
}

async function encryptedPageCount(input: string, password: string, cwd: string) {
  const result = await execute([input, "--password-mode=unicode", "--suppress-password-recovery", `--password=${password}`, "--show-npages"], cwd);
  const pages = Number(result.stdout.trim()); if (!Number.isSafeInteger(pages) || pages < 1 || pages > runtimeLimits.maxPages) throw new QpdfError("PAGE_LIMIT_EXCEEDED", "The decrypted PDF has an invalid or excessive page count."); return pages;
}
async function enforceObjectLimit(input: string, cwd: string, password?: string) { await execute([input, "--password-mode=unicode", ...(password === undefined ? [] : ["--suppress-password-recovery", `--password=${password}`]), "--show-xref"], cwd, [0, 3], runtimeLimits.maxPdfObjects); }
async function rejectSignedPdf(input: string, cwd: string) { const json = join(cwd, "structure.json"); await execute([input, "--json", "--json-key=objects", `--json-output=${json}`, "--decode-level=none"], cwd, [0, 3]); const details = await stat(json); if (details.size > 32 * 1024 * 1024) throw new QpdfError("PDF_OBJECT_LIMIT_EXCEEDED", "The PDF structure inventory exceeds the safe inspection limit."); const structure = await readFile(json, "utf8"); if (/ByteRange|\/Sig\b/u.test(structure)) throw new QpdfError("SIGNED_PDF_REPAIR_UNSAFE", "Signed PDFs are not rewritten because repair would invalidate signature integrity."); }

function encryptionArgs(input: string, output: string, userPassword: string, ownerPassword: string, permissionOptions?: PermissionOptions) {
  const permissions = permissionOptions ? [
    `--print=${permissionOptions.printing}`, `--extract=${permissionOptions.extraction ? "y" : "n"}`, `--assemble=${permissionOptions.assembly ? "y" : "n"}`,
    `--form=${permissionOptions.forms ? "y" : "n"}`, `--annotate=${permissionOptions.annotations ? "y" : "n"}`, "--accessibility=y", "--modify-other=n",
  ] : [];
  return [input, "--password-mode=unicode", "--encrypt", userPassword, ownerPassword, "256", "--force-R6", ...permissions, "--", output];
}

export async function runQpdfTool(tool: QpdfTool, inputBytes: Uint8Array, options: Record<string, unknown>, secrets?: Phase1SecretPayload) {
  const directory = await mkdtemp(join(tmpdir(), "dip-qpdf-")); await chmod(directory, 0o700); const input = join(directory, "input.pdf"); const output = join(directory, "output.pdf"); await writeFile(input, inputBytes, { mode: 0o600 });
  try {
    if (tool === "repair-pdf") {
      const encryption = await execute([input, "--is-encrypted"], directory, [0, 2]); if (encryption.code === 0) throw new QpdfError("ENCRYPTED_PDF_REPAIR_UNSUPPORTED", "Encrypted PDFs require decryption before repair.");
      await enforceObjectLimit(input, directory); await rejectSignedPdf(input, directory); await execute([input, output], directory, [0, 3]); await execute([output, "--check"], directory, [0, 3]); await enforceObjectLimit(output, directory); const bytes = new Uint8Array(await readFile(output)); await reopen(bytes); return { name: "repaired.pdf", mimeType: "application/pdf", bytes };
    }
    if (!secrets) throw new QpdfError("SECRET_REFERENCE_INVALID", "A secure password handoff is required.");
    if (tool === "unlock-pdf") {
      const password = secrets.password!; const pages = await encryptedPageCount(input, password, directory).catch((error) => { if (error instanceof QpdfError && error.code === "QPDF_PROCESSING_FAILED") throw new QpdfError("PDF_PASSWORD_INVALID", "The supplied password could not open this PDF."); throw error; }); await enforceObjectLimit(input, directory, password);
      await execute([input, "--password-mode=unicode", "--suppress-password-recovery", `--password=${password}`, "--decrypt", output], directory).catch((error) => { if (error instanceof QpdfError) throw new QpdfError("PDF_PASSWORD_INVALID", "The supplied password could not decrypt this PDF."); throw error; });
      const bytes = new Uint8Array(await readFile(output)); await reopen(bytes, pages); return { name: "unlocked.pdf", mimeType: "application/pdf", bytes };
    }
    const source = await PDFDocument.load(inputBytes, { ignoreEncryption: false }).catch(() => { throw new QpdfError("PDF_INVALID", "The input must be a valid unencrypted PDF."); }); const pages = source.getPageCount(); if (pages > runtimeLimits.maxPages) throw new QpdfError("PAGE_LIMIT_EXCEEDED", "The PDF exceeds the configured page limit."); await enforceObjectLimit(input, directory);
    const user = tool === "pdf-permissions" ? secrets.userPassword ?? "" : secrets.userPassword!; const owner = secrets.ownerPassword!;
    const permissionOptions: PermissionOptions | undefined = tool === "pdf-permissions" ? { printing: String(options.printing ?? "full") as PermissionOptions["printing"], extraction: options.extraction !== false, assembly: options.assembly !== false, forms: options.forms !== false, annotations: options.annotations !== false } : undefined;
    await execute(encryptionArgs(input, output, user, owner, permissionOptions), directory);
    await execute([output, "--password-mode=unicode", "--suppress-password-recovery", `--password=${owner}`, "--check"], directory, [0, 3]);
    const encrypted = await execute([output, "--is-encrypted"], directory, [0, 2]); if (encrypted.code !== 0) throw new QpdfError("OUTPUT_VALIDATION_FAILED", "qpdf did not produce an encrypted PDF.");
    const verifiedPages = await encryptedPageCount(output, owner, directory); if (verifiedPages !== pages) throw new QpdfError("OUTPUT_VALIDATION_FAILED", "The encrypted PDF page count changed.");
    return { name: tool === "protect-pdf" ? "protected.pdf" : "permissions.pdf", mimeType: "application/pdf", bytes: new Uint8Array(await readFile(output)) };
  } finally { await rm(directory, { recursive: true, force: true }); }
}
