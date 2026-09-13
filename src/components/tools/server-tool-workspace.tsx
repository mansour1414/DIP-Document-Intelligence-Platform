"use client";

import { useRef, useState } from "react";
import { Download, FileText, Languages, Lock, ScanText, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LanguageToggle, useLocale } from "@/components/i18n/locale-provider";
import type { ToolDefinition } from "@/config";
import { UploadZone } from "@/components/ui/upload-zone";
import { Progress } from "@/components/ui/progress";
import { StatusFeedback } from "@/components/ui/status-feedback";
import { BrandMark } from "@/components/brand/brand-mark";

export function ServerToolWorkspace({ tool, embedded: _embedded = false }: { tool: ToolDefinition; embedded?: boolean }) {
  void _embedded;
  const { locale } = useLocale();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [language, setLanguage] = useState("ara+eng");
  const [status, setStatus] = useState<"idle" | "processing" | "done" | "error">("idle");
  const [message, setMessage] = useState("");
  const [output, setOutput] = useState<{ url: string; name: string } | null>(null);
  const isOcr = tool.id === "ocr-pdf";
  const isArabic = locale === "ar";
  const copy = isArabic ? { isolated: "معالجة خادمية معزولة", temporary: "يُعالَج الملف في مساحة مؤقتة ومعزولة، ثم يُحذف مباشرةً بعد إنشاء النتيجة.", upload: "حمّل مستنداً ممسوحاً", uploadOne: "حمّل مستنداً واحداً", drop: "اسحب ملفاً هنا أو اختره", limit: "ملف واحد، حتى 100 ميجابايت", recognition: "لغة التعرّف", searchable: "يضيف OCR طبقة نص قابلة للبحث مع الحفاظ على شكل الصفحات الأصلي.", process: "تتم المعالجة بأمان…", searchableAction: "اجعل المستند قابلاً للبحث", ready: "أصبح المستند المحوّل جاهزاً. لا يحتفظ DIP به.", waiting: "قد تستغرق معالجة الملفات الممسوحة الكبيرة عدة دقائق.", download: "تحميل", remove: "إزالة" } : { isolated: "Isolated server processing", temporary: "The file is processed in a temporary isolated workspace and removed after the result is created.", upload: "Upload a scanned document", uploadOne: "Upload one document", drop: "Drop a file here or browse", limit: "One file, up to 100 MB", recognition: "Recognition language", searchable: "OCR adds a searchable text layer while preserving the original page appearance.", process: "Processing securely…", searchableAction: "Make document searchable", ready: "Your converted document is ready. It is not retained by DIP.", waiting: "Processing may take a few minutes for large scanned files.", download: "Download", remove: "Remove" };
  const accept = tool.id === "word-to-pdf" ? ".doc,.docx,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document" : tool.id === "excel-to-pdf" ? ".xls,.xlsx,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" : tool.id === "powerpoint-to-pdf" ? ".ppt,.pptx,application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.presentationml.presentation" : isOcr ? ".pdf,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png" : ".pdf,application/pdf";

  const select = (candidate?: File) => {
    if (!candidate) return;
    if (candidate.size > tool.limits.maxBytes) { setStatus("error"); setMessage("FILE_LIMIT: Choose a file no larger than 100 MB."); return; }
    if (output) URL.revokeObjectURL(output.url);
    setOutput(null); setFile(candidate); setStatus("idle"); setMessage("");
  };
  const process = async () => {
    if (!file) return;
    window.dispatchEvent(new CustomEvent("dip:analytics", { detail: { name: "tool_started" } })); setStatus("processing"); setMessage(isArabic ? "يجري إرسال المستند إلى محرك المعالجة المعزول…" : "Securely sending the document to the isolated processing engine…");
    const form = new FormData(); form.set("file", file); if (isOcr) form.set("language", language);
    try {
      const response = await fetch(`/api/tools/${tool.id}`, { method: "POST", body: form });
      if (!response.ok) { const problem = await response.json().catch(() => null); throw new Error(`${problem?.code ?? "PROCESSING_FAILED"}: ${problem?.message ?? "The document could not be processed."}`); }
      const disposition = response.headers.get("content-disposition") ?? "";
      const name = disposition.match(/filename="?([^";]+)"?/)?.[1] ?? `${file.name}.output`;
      const url = URL.createObjectURL(await response.blob());
      setOutput({ url, name }); setStatus("done"); setMessage(copy.ready); window.dispatchEvent(new CustomEvent("dip:analytics", { detail: { name: "tool_completed" } }));
    } catch (error) { setStatus("error"); setMessage(error instanceof Error ? error.message : "PROCESSING_FAILED: The document could not be processed."); window.dispatchEvent(new CustomEvent("dip:analytics", { detail: { name: "tool_failed", error_code: "PROCESSING_FAILED" } })); }
  };
  return <main className="min-h-screen bg-muted/35 text-foreground"><header className="border-b bg-card"><div className="mx-auto flex min-h-16 max-w-5xl items-center gap-3 px-4 sm:px-6"><BrandMark href="/" /><span aria-hidden="true" className="text-border">/</span><span className="flex-1 font-semibold">{isArabic ? tool.nameAr : tool.name}</span><LanguageToggle /></div></header><div className="mx-auto max-w-3xl px-4 py-10 sm:px-6"><div className="mb-7"><div className="mb-3 inline-flex items-center gap-2 rounded-full bg-secondary px-3 py-1 text-sm font-semibold text-secondary-foreground"><Lock aria-hidden="true" className="h-4 w-4" />{copy.isolated}</div><h1 className="text-3xl font-bold tracking-tight sm:text-4xl">{isArabic ? tool.nameAr : tool.name}</h1><p className="mt-3 max-w-2xl text-base leading-7 text-muted-foreground">{isArabic ? tool.descriptionAr : tool.description}. {copy.temporary}</p></div><Card><CardHeader><CardTitle>{isOcr ? copy.upload : copy.uploadOne}</CardTitle></CardHeader><CardContent className="space-y-6"><UploadZone title={copy.drop} description={copy.limit} hint={isArabic ? "تحقق آمن ومعالجة معزولة" : "Secure validation and isolated processing"} invalid={status === "error" && !file} onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); select(event.dataTransfer.files.item(0) ?? undefined); }} /><input ref={inputRef} className="sr-only" type="file" accept={accept} onChange={(event) => select(event.target.files?.[0])} />{file && <div className="flex min-h-14 items-center gap-3 rounded-xl border bg-card px-3 shadow-sm"><FileText aria-hidden="true" className="h-5 w-5 shrink-0 text-primary" /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{file.name}</p><p className="text-xs text-muted-foreground">{(file.size / 1024 / 1024).toFixed(2)} MB</p></div><Button aria-label={`${copy.remove} ${file.name}`} variant="ghost" size="icon" onClick={() => { setFile(null); setOutput(null); setStatus("idle"); }}><X className="h-4 w-4" /></Button></div>}{isOcr && <fieldset className="rounded-xl border bg-muted/30 p-4"><legend className="px-1 text-sm font-medium">{copy.recognition}</legend><div className="mt-2 flex flex-wrap gap-3">{[["ara+eng", isArabic ? "العربية والإنجليزية" : "Arabic + English"], ["ara", isArabic ? "العربية" : "Arabic"], ["eng", isArabic ? "الإنجليزية" : "English"]].map(([value, label]) => <label key={value} className="flex min-h-11 items-center gap-2 text-sm"><input className="accent-primary" type="radio" name="ocr-language" value={value} checked={language === value} onChange={() => setLanguage(value)} /><Languages aria-hidden="true" className="h-4 w-4 text-muted-foreground" />{label}</label>)}</div><p className="mt-3 text-sm text-muted-foreground"><ScanText aria-hidden="true" className="me-1 inline h-4 w-4" />{copy.searchable}</p></fieldset>}<Button className="min-h-12 w-full" size="lg" disabled={!file || status === "processing"} onClick={process}>{status === "processing" ? copy.process : isOcr ? copy.searchableAction : `${isArabic ? "تحويل إلى" : "Convert to"} ${tool.id === "pdf-to-word" ? "Word" : "PDF"}`}</Button>{status === "processing" && <div className="dip-ai-card relative overflow-hidden rounded-2xl border border-info/30 bg-info-surface/35 p-5" data-streaming="true" role="status"><div aria-hidden="true" className="dip-laser"/><p className="relative font-semibold">{copy.process}</p><p className="relative mt-1 text-sm text-muted-foreground">{copy.waiting}</p><Progress className="relative mt-4" label={copy.waiting} /></div>}{message && <StatusFeedback status={status === "error" ? "error" : status === "done" ? "success" : "info"}>{message}</StatusFeedback>}{output && <Button className="w-full" variant="outline" asChild><a href={output.url} download={output.name}><Download aria-hidden="true" className="h-4 w-4" />{copy.download} {output.name}</a></Button>}</CardContent></Card></div></main>;
}
