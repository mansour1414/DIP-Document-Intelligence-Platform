"use client";

import { useRef, useState } from "react";
import Link from "next/link";
import { CheckCircle2, Download, FileText, Languages, Lock, ScanText, Upload, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ToolDefinition } from "@/config";

export function ServerToolWorkspace({ tool }: { tool: ToolDefinition }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [language, setLanguage] = useState("ara+eng");
  const [status, setStatus] = useState<"idle" | "processing" | "done" | "error">("idle");
  const [message, setMessage] = useState("");
  const [output, setOutput] = useState<{ url: string; name: string } | null>(null);
  const isOcr = tool.id === "ocr-pdf";
  const accept = tool.id === "word-to-pdf" ? ".doc,.docx,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document" : isOcr ? ".pdf,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png" : ".pdf,application/pdf";

  const select = (candidate?: File) => {
    if (!candidate) return;
    if (candidate.size > tool.limits.maxBytes) { setStatus("error"); setMessage("FILE_LIMIT: Choose a file no larger than 100 MB."); return; }
    if (output) URL.revokeObjectURL(output.url);
    setOutput(null); setFile(candidate); setStatus("idle"); setMessage("");
  };
  const process = async () => {
    if (!file) return;
    setStatus("processing"); setMessage("Securely sending the document to the isolated processing engine…");
    const form = new FormData(); form.set("file", file); if (isOcr) form.set("language", language);
    try {
      const response = await fetch(`/api/tools/${tool.id}`, { method: "POST", body: form });
      if (!response.ok) { const problem = await response.json().catch(() => null); throw new Error(`${problem?.code ?? "PROCESSING_FAILED"}: ${problem?.message ?? "The document could not be processed."}`); }
      const disposition = response.headers.get("content-disposition") ?? "";
      const name = disposition.match(/filename="?([^";]+)"?/)?.[1] ?? `${file.name}.output`;
      const url = URL.createObjectURL(await response.blob());
      setOutput({ url, name }); setStatus("done"); setMessage("Your converted document is ready. It is not retained by DIP.");
    } catch (error) { setStatus("error"); setMessage(error instanceof Error ? error.message : "PROCESSING_FAILED: The document could not be processed."); }
  };
  return <main className="min-h-screen bg-slate-50 text-slate-950"><header className="border-b border-slate-200 bg-white"><div className="mx-auto flex h-16 max-w-5xl items-center gap-3 px-4 sm:px-6"><Link href="/" className="rounded-lg bg-blue-700 px-2.5 py-1.5 text-sm font-bold text-white">DIP</Link><span aria-hidden="true" className="text-slate-300">/</span><span className="font-semibold">{tool.name}</span></div></header><div className="mx-auto max-w-3xl px-4 py-10 sm:px-6"><div className="mb-7"><div className="mb-3 inline-flex items-center gap-2 rounded-full bg-violet-50 px-3 py-1 text-sm font-medium text-violet-800"><Lock aria-hidden="true" className="h-4 w-4" />Isolated server processing</div><h1 className="text-3xl font-bold tracking-tight sm:text-4xl">{tool.name}</h1><p className="mt-3 max-w-2xl text-base leading-7 text-slate-600">{tool.description}. The file is processed in a temporary isolated workspace and removed after the result is created.</p></div><Card><CardHeader><CardTitle>{isOcr ? "Upload a scanned document" : "Upload one document"}</CardTitle></CardHeader><CardContent className="space-y-6"><button type="button" onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); select(event.dataTransfer.files.item(0) ?? undefined); }} className="flex min-h-48 w-full flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-300 bg-slate-50 px-6 text-center transition-colors hover:border-blue-500 hover:bg-blue-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-600"><Upload aria-hidden="true" className="mb-4 h-9 w-9 text-blue-700" /><span className="font-semibold">Drop a file here or browse</span><span className="mt-2 text-sm text-slate-600">One file, up to 100 MB</span></button><input ref={inputRef} className="sr-only" type="file" accept={accept} onChange={(event) => select(event.target.files?.[0])} />{file && <div className="flex min-h-14 items-center gap-3 rounded-lg border border-slate-200 bg-white px-3"><FileText aria-hidden="true" className="h-5 w-5 shrink-0 text-blue-700" /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{file.name}</p><p className="text-xs text-slate-500">{(file.size / 1024 / 1024).toFixed(2)} MB</p></div><Button aria-label={`Remove ${file.name}`} variant="ghost" size="icon" onClick={() => { setFile(null); setOutput(null); setStatus("idle"); }}><X className="h-4 w-4" /></Button></div>}{isOcr && <fieldset className="rounded-lg border border-slate-200 p-4"><legend className="px-1 text-sm font-medium">Recognition language</legend><div className="mt-2 flex flex-wrap gap-3">{[["ara+eng", "Arabic + English"], ["ara", "Arabic"], ["eng", "English"]].map(([value, label]) => <label key={value} className="flex items-center gap-2 text-sm"><input type="radio" name="ocr-language" value={value} checked={language === value} onChange={() => setLanguage(value)} /><Languages aria-hidden="true" className="h-4 w-4 text-slate-500" />{label}</label>)}</div><p className="mt-3 text-sm text-slate-600"><ScanText aria-hidden="true" className="mr-1 inline h-4 w-4" />OCR adds a searchable text layer while preserving the original page appearance.</p></fieldset>}<Button className="min-h-12 w-full" size="lg" disabled={!file || status === "processing"} onClick={process}>{status === "processing" ? "Processing securely…" : isOcr ? "Make document searchable" : `Convert to ${tool.id === "word-to-pdf" ? "PDF" : "Word"}`}</Button>{status === "processing" && <div className="space-y-2" role="status"><p className="text-sm text-blue-800">Processing may take a few minutes for large scanned files.</p><div className="h-2 overflow-hidden rounded-full bg-blue-100"><div className="h-full w-2/3 animate-pulse rounded-full bg-blue-700" /></div></div>}{message && <div role={status === "error" ? "alert" : "status"} className={`rounded-lg px-4 py-3 text-sm ${status === "error" ? "bg-red-50 text-red-800" : status === "done" ? "bg-emerald-50 text-emerald-800" : "bg-blue-50 text-blue-800"}`}>{status === "done" && <CheckCircle2 aria-hidden="true" className="mr-2 inline h-4 w-4" />}{message}</div>}{output && <Button className="w-full" variant="outline" asChild><a href={output.url} download={output.name}><Download aria-hidden="true" className="h-4 w-4" />Download {output.name}</a></Button>}</CardContent></Card></div></main>;
}
