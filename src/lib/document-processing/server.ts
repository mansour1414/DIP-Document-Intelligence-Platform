import { mkdtemp, readdir, readFile, rm, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { basename, extname, join } from "path";
import { spawn } from "child_process";
import { runtimeLimits, timeoutFor } from "@/lib/runtime/config";
import { recordMetric } from "@/lib/observability/metrics";
import { PDFDocument } from "pdf-lib";

export type ServerToolId = "word-to-pdf" | "pdf-to-word" | "excel-to-pdf" | "powerpoint-to-pdf" | "ocr-pdf";


export class DocumentProcessingError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
  }
}

function safeFilename(name: string) {
  const clean = basename(name).replace(/[^\w.()-]/g, "_");
  return clean || "document";
}

async function run(command: string, args: string[], cwd: string, timeoutMs: number) {
  return new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, { cwd, shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    const collect = (chunk: Buffer) => { output = `${output}${chunk.toString()}`.slice(-12_000); };
    child.stdout.on("data", collect); child.stderr.on("data", collect);
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGTERM"); setTimeout(() => child.kill("SIGKILL"), 2_000).unref(); }, timeoutMs);
    child.once("error", (error: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(new DocumentProcessingError(error.code === "ENOENT" ? "ENGINE_UNAVAILABLE" : "ENGINE_FAILED", error.code === "ENOENT" ? `The ${command} processing engine is not installed on this server.` : "The document processing engine could not start."));
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new DocumentProcessingError(timedOut ? "PROCESSING_TIMEOUT" : "ENGINE_FAILED", timedOut ? "The processing engine exceeded its time limit." : output.trim() || "The conversion engine could not process this document."));
    });
  });
}

function outputName(inputName: string, extension: ".pdf" | ".docx") {
  return `${basename(safeFilename(inputName), extname(inputName))}${extension}`;
}

export async function processServerDocument(tool: ServerToolId, file: File, language = "ara+eng") {
  if (file.size === 0 || file.size > runtimeLimits.maxInputBytes) throw new DocumentProcessingError("FILE_LIMIT", "Choose a non-empty file within the configured size limit.");
  const name = safeFilename(file.name);
  const inputExtension = extname(name).toLowerCase();
  const accepted = tool === "word-to-pdf"
    ? [".doc", ".docx"].includes(inputExtension)
    : tool === "excel-to-pdf"
      ? [".xls", ".xlsx"].includes(inputExtension)
      : tool === "powerpoint-to-pdf"
        ? [".ppt", ".pptx"].includes(inputExtension)
    : tool === "pdf-to-word"
      ? inputExtension === ".pdf"
      : [".pdf", ".jpg", ".jpeg", ".png"].includes(inputExtension);
  if (!accepted) throw new DocumentProcessingError("UNSUPPORTED_FILE", "This file type is not supported by the selected tool.");

  const directory = await mkdtemp(join(tmpdir(), "dip-process-"));
  try {
    // The directory is unique per request, so preserving the sanitized source
    // name lets LibreOffice produce a predictable output name.
    // `directory` is an os.tmpdir() child created above and `name` is sanitized.
    // Turbopack cannot prove that boundary and would otherwise trace the repository.
    const inputPath = join(/* turbopackIgnore: true */ directory, name);
    await writeFile(inputPath, Buffer.from(await file.arrayBuffer()));
    const outputExtension = tool === "pdf-to-word" ? ".docx" : ".pdf";

    const started = performance.now();
    if (tool === "ocr-pdf") {
      // Standard PDF output plus optimize=0 avoids the Ghostscript PDF/A and
      // optimization paths. Production images must still verify the resolved chain.
      await run("ocrmypdf", ["--skip-text", "--rotate-pages", "--deskew", "--output-type", "pdf", "--optimize", "0", "--language", language, inputPath, join(directory, outputName(name, ".pdf"))], directory, timeoutFor("ocr"));
    } else {
      // LibreOffice is isolated behind this server-only boundary. It handles DOC/DOCX reliably;
      // PDF-to-DOCX quality depends on the LibreOffice/PDF import filter installed by the host.
      const profile = join(directory, "lo-profile").replaceAll("\\", "/");
      await run("soffice", [`-env:UserInstallation=file:///${profile}`, "--headless", "--nologo", "--nodefault", "--nolockcheck", "--norestore", "--convert-to", outputExtension === ".pdf" ? "pdf" : "docx", "--outdir", directory, inputPath], directory, timeoutFor("office"));
    }
    const duration = performance.now() - started;

    const expected = outputName(name, outputExtension);
    const generated = (await readdir(directory)).find((item) => item.toLowerCase() === expected.toLowerCase());
    if (!generated) throw new DocumentProcessingError("NO_OUTPUT", "The processing engine finished without creating an output file.");
    const bytes = await readFile(join(directory, generated));
    const metricDuration = tool === "ocr-pdf" ? duration / Math.max(1, (await PDFDocument.load(bytes)).getPageCount()) : duration;
    recordMetric(tool === "ocr-pdf" ? "ocr_duration_per_page" : "tool_execution_duration_ms", metricDuration, "ms", { tool_id: tool, engine: tool === "ocr-pdf" ? "ocrmypdf" : "libreoffice", engine_version: "host", status: "succeeded" });
    return { bytes, filename: generated, contentType: outputExtension === ".pdf" ? "application/pdf" : "application/vnd.openxmlformats-officedocument.wordprocessingml.document" };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
