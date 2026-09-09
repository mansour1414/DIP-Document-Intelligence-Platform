"use client";

import { useCallback, useRef, useState } from "react";
import Link from "next/link";
import { ArrowDown, ArrowUp, CheckCircle2, Download, FileText, Lock, Upload, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { LanguageToggle, useLocale } from "@/components/i18n/locale-provider";
import { downloadOutput, PdfToolError, runPdfOperation, type OutputFile, type PdfOperation } from "@/lib/pdf/client";
import type { ToolDefinition } from "@/config";

type Props = { tool: ToolDefinition };

const pageInputTools = new Set(["split-pdf", "organize-pdf", "delete-pages", "extract-pages"]);
const workerBatch2Tools = new Set(["compress-pdf", "pdf-to-jpg", "watermark-pdf"]);

async function waitForWorkerJob(jobId: string) {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    const response = await fetch(`/api/jobs/status/${jobId}`, { cache: "no-store" }); const job = await response.json() as { status?: string; result?: { outputFileIds?: string[] }; errorCode?: string; error?: { message?: string } };
    if (!response.ok) throw new Error(job.errorCode ?? "JOB_STATUS_FAILED");
    if (job.status === "succeeded") return job.result?.outputFileIds ?? [];
    if (["failed", "cancelled", "expired"].includes(job.status ?? "")) throw new Error(`${job.errorCode ?? "PROCESSING_FAILED"}: ${job.error?.message ?? "The worker could not process this document."}`);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("PROCESSING_TIMEOUT: The worker did not finish in time.");
}

export function PdfToolWorkspace({ tool }: Props) {
  const { locale } = useLocale();
  const isArabic = locale === "ar";
  const operation = tool.id as PdfOperation;
  const inputRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [pages, setPages] = useState("");
  const [rotation, setRotation] = useState<90 | 180 | 270>(90);
  const [watermark, setWatermark] = useState("");
  const [quality, setQuality] = useState(operation === "compress-pdf" ? 0.72 : 0.9);
  const [progress, setProgress] = useState({ completed: 0, total: 0 });
  const [status, setStatus] = useState<"idle" | "processing" | "done" | "error">("idle");
  const [message, setMessage] = useState("");
  const [outputs, setOutputs] = useState<OutputFile[]>([]);

  const acceptsImages = operation === "jpg-to-pdf";
  const multiple = operation === "merge-pdf" || acceptsImages;

  const addFiles = useCallback((incoming: File[]) => {
    const accepted = incoming.filter((file) => acceptsImages ? ["image/jpeg", "image/png"].includes(file.type) : file.type === "application/pdf" || file.name.toLowerCase().endsWith(".pdf"));
    setFiles((current) => multiple ? [...current, ...accepted].slice(0, tool.limits.maxFiles) : accepted.slice(0, 1));
    setOutputs([]);
    setStatus("idle");
    setMessage(accepted.length === incoming.length ? "" : "Some unsupported files were ignored.");
  }, [acceptsImages, multiple, tool.limits.maxFiles]);

  const move = (index: number, direction: -1 | 1) => setFiles((current) => {
    const target = index + direction;
    if (target < 0 || target >= current.length) return current;
    const next = [...current];
    [next[index], next[target]] = [next[target], next[index]];
    return next;
  });

  const process = async () => {
    setStatus("processing"); setMessage("Reading and validating your files…"); setOutputs([]); setProgress({ completed: 0, total: 0 });
    let jobId: string | undefined;
    try {
      if (workerBatch2Tools.has(operation)) {
        const form = new FormData(); files.forEach((file) => form.append("files", file)); form.set("options", JSON.stringify({ quality, watermark }));
        const queued = await fetch(`/api/jobs/${operation}`, { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() }, body: form }); const accepted = await queued.json() as { jobId?: string; code?: string; message?: string };
        if (!queued.ok || !accepted.jobId) throw new Error(`${accepted.code ?? "QUEUE_FAILED"}: ${accepted.message ?? "The job could not be queued."}`);
        setMessage("Processing securely in the document worker…"); const outputFileIds = await waitForWorkerJob(accepted.jobId);
        const workerOutputs = await Promise.all(outputFileIds.map(async (fileId, index) => { const response = await fetch(`/api/files/${fileId}`); if (!response.ok) throw new Error("OUTPUT_DOWNLOAD_FAILED"); const disposition = response.headers.get("content-disposition") ?? ""; return { name: disposition.match(/filename="?([^";]+)"?/)?.[1] ?? `output-${index + 1}`, bytes: new Uint8Array(await response.arrayBuffer()), mimeType: response.headers.get("content-type") ?? "application/octet-stream" }; }));
        setOutputs(workerOutputs); setStatus("done"); setMessage(`${workerOutputs.length} file${workerOutputs.length === 1 ? "" : "s"} ready to download.`); return;
      }
      const authorization = await fetch("/api/usage", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ toolId: operation, filename: files.map((file) => file.name).join(", "), size: files.reduce((total, file) => total + file.size, 0), mimeType: files[0]?.type }) });
      const authorized = await authorization.json() as { jobId?: string; code?: string; message?: string };
      if (!authorization.ok || !authorized.jobId) throw new Error(`${authorized.code ?? "AUTH_REQUIRED"}: ${authorized.message ?? "Sign in to process documents."}`);
      jobId = authorized.jobId;
      const result = await runPdfOperation(operation, files, { pages, rotation, watermark, quality, onProgress: (completed, total) => {
        setProgress({ completed, total });
        setMessage(`Rendering page ${completed} of ${total}…`);
      } });
      await fetch("/api/usage", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jobId, success: true }) });
      setOutputs(result); setStatus("done"); setMessage(`${result.length} file${result.length === 1 ? "" : "s"} ready to download.`);
    } catch (error) {
      if (jobId) await fetch("/api/usage", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jobId, success: false, error: error instanceof Error ? error.message : "Processing failed" }) });
      const known = error instanceof PdfToolError;
      setStatus("error"); setMessage(known ? `${error.code}: ${error.message}` : "INTERNAL_ERROR: The document could not be processed.");
    }
  };

  return (
    <main className="min-h-screen bg-slate-50 text-slate-950">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex h-16 max-w-5xl items-center gap-3 px-4 sm:px-6">
          <Link href="/" className="rounded-lg bg-blue-700 px-2.5 py-1.5 text-sm font-bold text-white">DIP</Link>
          <span aria-hidden="true" className="text-slate-300">/</span><span className="flex-1 font-semibold">{isArabic ? tool.nameAr : tool.name}</span><LanguageToggle />
        </div>
      </header>
      <div className="mx-auto max-w-3xl px-4 py-10 sm:px-6">
        <div className="mb-7">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full bg-emerald-50 px-3 py-1 text-sm font-medium text-emerald-800"><Lock aria-hidden="true" className="h-4 w-4" />Private browser processing</div>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">{isArabic ? tool.nameAr : tool.name}</h1>
          <p className="mt-3 text-base leading-7 text-slate-600">{isArabic ? tool.descriptionAr : tool.description}. {isArabic ? "تبقى الملفات على هذا الجهاز في الأدوات التي تعمل من المتصفح." : "Files stay on this device for supported browser operations."}</p>
        </div>
        <Card>
          <CardHeader><CardTitle>Select {acceptsImages ? "images" : "PDF files"}</CardTitle></CardHeader>
          <CardContent className="space-y-6">
            <button type="button" onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); addFiles(Array.from(event.dataTransfer.files)); }} className="flex min-h-48 w-full flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-300 bg-slate-50 px-6 text-center transition-colors hover:border-blue-500 hover:bg-blue-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-600">
              <Upload aria-hidden="true" className="mb-4 h-9 w-9 text-blue-700" /><span className="font-semibold">Drop files here or browse</span><span className="mt-2 text-sm text-slate-600">Up to {tool.limits.maxFiles} files and 100 MB total</span>
            </button>
            <input ref={inputRef} className="sr-only" type="file" accept={acceptsImages ? "image/jpeg,image/png" : "application/pdf,.pdf"} multiple={multiple} onChange={(event) => addFiles(Array.from(event.target.files ?? []))} />
            {files.length > 0 && <ul aria-label="Selected files" className="space-y-2">{files.map((file, index) => <li key={`${file.name}-${file.lastModified}-${index}`} className="flex min-h-14 items-center gap-3 rounded-lg border border-slate-200 bg-white px-3">
              <FileText aria-hidden="true" className="h-5 w-5 shrink-0 text-red-600" /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{file.name}</p><p className="text-xs text-slate-500">{(file.size / 1024 / 1024).toFixed(2)} MB</p></div>
              {multiple && <><Button aria-label={`Move ${file.name} up`} variant="ghost" size="icon" disabled={index === 0} onClick={() => move(index, -1)}><ArrowUp className="h-4 w-4" /></Button><Button aria-label={`Move ${file.name} down`} variant="ghost" size="icon" disabled={index === files.length - 1} onClick={() => move(index, 1)}><ArrowDown className="h-4 w-4" /></Button></>}
              <Button aria-label={`Remove ${file.name}`} variant="ghost" size="icon" onClick={() => setFiles((current) => current.filter((_, itemIndex) => itemIndex !== index))}><X className="h-4 w-4" /></Button>
            </li>)}</ul>}
            {pageInputTools.has(operation) && <label className="block text-sm font-medium">{operation === "organize-pdf" ? "New page order" : "Pages"}<Input className="mt-2" value={pages} onChange={(event) => setPages(event.target.value)} placeholder={operation === "organize-pdf" ? "3, 1, 2, 4-6" : "1-3, 5"} /></label>}
            {operation === "rotate-pdf" && <label className="block text-sm font-medium">Rotation<Input className="mt-2" type="number" min={90} max={270} step={90} value={rotation} onChange={(event) => setRotation(Number(event.target.value) as 90 | 180 | 270)} /></label>}
            {operation === "watermark-pdf" && <label className="block text-sm font-medium">Watermark text<Input className="mt-2" value={watermark} maxLength={80} onChange={(event) => setWatermark(event.target.value)} placeholder="Confidential" /></label>}
            {(operation === "compress-pdf" || operation === "pdf-to-jpg") && <label className="block text-sm font-medium">Image quality: {Math.round(quality * 100)}%<input className="mt-3 block w-full accent-blue-700" type="range" min="0.45" max="0.95" step="0.05" value={quality} onChange={(event) => setQuality(Number(event.target.value))} /></label>}
            <Button className="min-h-12 w-full" size="lg" disabled={!files.length || status === "processing" || (operation === "merge-pdf" && files.length < 2)} onClick={process}>{status === "processing" ? "Processing…" : `Process ${files.length || ""} file${files.length === 1 ? "" : "s"}`}</Button>
            {status === "processing" && progress.total > 0 && <div aria-label={`Processed ${progress.completed} of ${progress.total} pages`} className="h-2 overflow-hidden rounded-full bg-slate-200"><div className="h-full rounded-full bg-blue-700 transition-[width]" style={{ width: `${(progress.completed / progress.total) * 100}%` }} /></div>}
            {message && <div role={status === "error" ? "alert" : "status"} className={`rounded-lg px-4 py-3 text-sm ${status === "error" ? "bg-red-50 text-red-800" : status === "done" ? "bg-emerald-50 text-emerald-800" : "bg-blue-50 text-blue-800"}`}>{status === "done" && <CheckCircle2 aria-hidden="true" className="mr-2 inline h-4 w-4" />}{message}</div>}
            {outputs.length > 0 && <div className="grid gap-2 sm:grid-cols-2">{outputs.map((output) => <Button key={output.name} variant="outline" onClick={() => downloadOutput(output)}><Download aria-hidden="true" className="h-4 w-4" />{output.name}</Button>)}</div>}
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
