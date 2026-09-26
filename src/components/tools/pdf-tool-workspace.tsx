"use client";

import { useCallback, useRef, useState } from "react";
import { ArrowDown, ArrowUp, CheckCircle2, Download, FileText, Lock, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { LanguageToggle, useLocale } from "@/components/i18n/locale-provider";
import { downloadOutput, PdfToolError, runPdfOperation, type OutputFile, type PdfOperation } from "@/lib/pdf/client";
import type { ToolDefinition } from "@/config";
import { UploadZone } from "@/components/ui/upload-zone";
import { Progress } from "@/components/ui/progress";
import { StatusFeedback } from "@/components/ui/status-feedback";
import { BrandMark } from "@/components/brand/brand-mark";

type Props = { tool: ToolDefinition; embedded?: boolean };

const pageInputTools = new Set(["split-pdf", "organize-pdf", "delete-pages", "extract-pages"]);
const workerPdfTools = new Set(["compress-pdf", "pdf-to-jpg", "watermark-pdf", "crop-pdf", "page-numbers", "header-footer", "resize-pages", "alternate-mix", "flip-pages", "split-pdf-by-size", "split-pdf-by-bookmarks", "split-pdf-by-text", "n-up-pdf", "remove-annotations", "extract-images", "protect-pdf", "unlock-pdf", "pdf-permissions", "repair-pdf"]);

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

export function PdfToolWorkspace({ tool, embedded = false }: Props) {
  const { locale } = useLocale();
  const isArabic = locale === "ar";
  const operation = tool.id as PdfOperation;
  const inputRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [pages, setPages] = useState("");
  const [rotation, setRotation] = useState<90 | 180 | 270>(90);
  const [watermark, setWatermark] = useState("");
  const [quality, setQuality] = useState(operation === "compress-pdf" ? 0.72 : 0.9);
  const [crop, setCrop] = useState({ topPercent: 5, rightPercent: 5, bottomPercent: 5, leftPercent: 5 });
  const [numberFormat, setNumberFormat] = useState("{page} / {total}");
  const [numberPosition, setNumberPosition] = useState("bottom-center");
  const [headerText, setHeaderText] = useState("");
  const [footerText, setFooterText] = useState("");
  const [alignment, setAlignment] = useState("center");
  const [pageSize, setPageSize] = useState("a4");
  const [resizeOrientation, setResizeOrientation] = useState("preserve");
  const [resizeFit, setResizeFit] = useState("contain");
  const [mixStart, setMixStart] = useState("first");
  const [reverseSecond, setReverseSecond] = useState(false);
  const [flipAxis, setFlipAxis] = useState("horizontal");
  const [flipPageRange, setFlipPageRange] = useState("");
  const [targetSizeMb, setTargetSizeMb] = useState(10);
  const [matchText, setMatchText] = useState("");
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [nUpLayout, setNUpLayout] = useState(2);
  const [nUpOrientation, setNUpOrientation] = useState("portrait");
  const [nUpOrder, setNUpOrder] = useState("row");
  const [annotationPolicy, setAnnotationPolicy] = useState("comments");
  const [userPassword, setUserPassword] = useState("");
  const [ownerPassword, setOwnerPassword] = useState("");
  const [unlockPassword, setUnlockPassword] = useState("");
  const [authorizedUse, setAuthorizedUse] = useState(false);
  const [permissions, setPermissions] = useState({ printing: "full", extraction: true, assembly: true, forms: true, annotations: true });
  const [progress, setProgress] = useState({ completed: 0, total: 0 });
  const [status, setStatus] = useState<"idle" | "processing" | "done" | "error">("idle");
  const [message, setMessage] = useState("");
  const [outputs, setOutputs] = useState<OutputFile[]>([]);

  const acceptsImages = operation === "jpg-to-pdf";
  const multiple = operation === "merge-pdf" || operation === "alternate-mix" || acceptsImages;

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
    window.dispatchEvent(new CustomEvent("dip:analytics", { detail: { name: "tool_started" } }));
    setStatus("processing"); setMessage("Reading and validating your files…"); setOutputs([]); setProgress({ completed: 0, total: 0 });
    let jobId: string | undefined;
    try {
      if (workerPdfTools.has(operation)) {
        const options: Record<string, string | number | boolean> = operation === "compress-pdf" || operation === "pdf-to-jpg" ? { quality }
          : operation === "watermark-pdf" ? { watermark }
          : operation === "crop-pdf" ? crop
          : operation === "page-numbers" ? { format: numberFormat, position: numberPosition, startNumber: 1, fontSize: 12, margin: 24 }
          : operation === "header-footer" ? { headerText, footerText, alignment, fontSize: 12, margin: 24 }
          : operation === "resize-pages" ? { pageSize, orientation: resizeOrientation, fit: resizeFit }
          : operation === "alternate-mix" ? { startWith: mixStart, reverseSecond }
          : operation === "split-pdf-by-size" ? { targetSizeMb }
          : operation === "split-pdf-by-text" ? { matchText, caseSensitive }
          : operation === "n-up-pdf" ? { layout: nUpLayout, orientation: nUpOrientation, pageSize: pageSize === "letter" ? "letter" : "a4", margin: 18, order: nUpOrder }
          : operation === "remove-annotations" ? { policy: annotationPolicy }
          : operation === "pdf-permissions" ? permissions
          : ["extract-images", "protect-pdf", "unlock-pdf", "repair-pdf"].includes(operation) ? {}
          : operation === "split-pdf-by-bookmarks" ? {}
          : { axis: flipAxis, ...(flipPageRange.trim() ? { pages: flipPageRange } : {}) };
        const form = new FormData(); files.forEach((file) => form.append("files", file)); form.set("options", JSON.stringify(options));
        if (operation === "protect-pdf" || operation === "pdf-permissions") { form.set("userPassword", userPassword); form.set("ownerPassword", ownerPassword); }
        if (operation === "unlock-pdf") { form.set("password", unlockPassword); form.set("authorizedUseAcknowledged", String(authorizedUse)); }
        const queued = await fetch(`/api/jobs/${operation}`, { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID() }, body: form }); const accepted = await queued.json() as { jobId?: string; code?: string; message?: string };
        if (!queued.ok || !accepted.jobId) throw new Error(`${accepted.code ?? "QUEUE_FAILED"}: ${accepted.message ?? "The job could not be queued."}`);
        setUserPassword(""); setOwnerPassword(""); setUnlockPassword("");
        setMessage("Processing securely in the document worker…"); const outputFileIds = await waitForWorkerJob(accepted.jobId);
        const workerOutputs = await Promise.all(outputFileIds.map(async (fileId, index) => { const response = await fetch(`/api/files/${fileId}`); if (!response.ok) throw new Error("OUTPUT_DOWNLOAD_FAILED"); const disposition = response.headers.get("content-disposition") ?? ""; return { name: disposition.match(/filename="?([^";]+)"?/)?.[1] ?? `output-${index + 1}`, bytes: new Uint8Array(await response.arrayBuffer()), mimeType: response.headers.get("content-type") ?? "application/octet-stream" }; }));
        setOutputs(workerOutputs); setStatus("done"); setMessage(`${workerOutputs.length} file${workerOutputs.length === 1 ? "" : "s"} ready to download.`); window.dispatchEvent(new CustomEvent("dip:analytics", { detail: { name: "tool_completed" } })); return;
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
      setOutputs(result); setStatus("done"); setMessage(`${result.length} file${result.length === 1 ? "" : "s"} ready to download.`); window.dispatchEvent(new CustomEvent("dip:analytics", { detail: { name: "tool_completed" } }));
    } catch (error) {
      if (jobId) await fetch("/api/usage", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jobId, success: false, error: error instanceof Error ? error.message : "Processing failed" }) });
      const known = error instanceof PdfToolError; const safeMessage = error instanceof Error && /^[A-Z0-9_]+:/u.test(error.message) ? error.message : "INTERNAL_ERROR: The document could not be processed.";
      setStatus("error"); setMessage(known ? `${error.code}: ${error.message}` : safeMessage); window.dispatchEvent(new CustomEvent("dip:analytics", { detail: { name: "tool_failed", error_code: known ? error.code : safeMessage.split(":", 1)[0] } }));
    }
  };

  return (
    <div className={embedded ? "text-foreground" : "min-h-screen bg-muted/35 text-foreground"}>
      {!embedded && <header className="border-b border-border bg-card">
        <div className="mx-auto flex h-16 max-w-5xl items-center gap-3 px-4 sm:px-6">
          <BrandMark href="/" /><span aria-hidden="true" className="text-border">/</span><span className="flex-1 font-semibold">{isArabic ? tool.nameAr : tool.name}</span><LanguageToggle />
        </div>
      </header>}
      <div className={embedded ? "mx-auto max-w-3xl" : "mx-auto max-w-3xl px-4 py-10 sm:px-6"}>
        <div className="mb-7">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full bg-success-surface px-3 py-1 text-sm font-semibold text-success"><Lock aria-hidden="true" className="h-4 w-4" />{workerPdfTools.has(operation) ? (isArabic ? "معالجة خادمية معزولة" : "Isolated server processing") : (isArabic ? "معالجة خاصة داخل المتصفح" : "Private browser processing")}</div>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">{isArabic ? tool.nameAr : tool.name}</h1>
          <p className="mt-3 text-base leading-7 text-muted-foreground">{isArabic ? tool.descriptionAr : tool.description}. {workerPdfTools.has(operation) ? (isArabic ? "يُعالج الملف في عامل مستندات معزول وتُطبق عليه سياسة الاحتفاظ." : "The file is processed by an isolated document worker under the retention policy.") : (isArabic ? "تبقى الملفات على هذا الجهاز في الأدوات التي تعمل من المتصفح." : "Files stay on this device for supported browser operations.")}</p>
        </div>
        <Card>
          <CardHeader><CardTitle>Select {acceptsImages ? "images" : "PDF files"}</CardTitle></CardHeader>
          <CardContent className="space-y-6">
            <UploadZone title="Drop files here or browse" description={`Up to ${tool.limits.maxFiles} files and 100 MB total`} hint="Private, validated processing" invalid={status === "error" && files.length === 0} onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); addFiles(Array.from(event.dataTransfer.files)); }} />
            <input ref={inputRef} className="sr-only" type="file" accept={acceptsImages ? "image/jpeg,image/png" : "application/pdf,.pdf"} multiple={multiple} aria-label={acceptsImages ? "Select images" : "Select PDF files"} onChange={(event) => addFiles(Array.from(event.target.files ?? []))} />
            {files.length > 0 && <ul aria-label="Selected files" className="space-y-2">{files.map((file, index) => <li key={`${file.name}-${file.lastModified}-${index}`} className="flex min-h-14 items-center gap-2 rounded-xl border bg-card px-3 shadow-sm sm:gap-3">
              <FileText aria-hidden="true" className="h-5 w-5 shrink-0 text-primary" /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{file.name}</p><p className="text-xs text-muted-foreground">{(file.size / 1024 / 1024).toFixed(2)} MB</p></div><span className="hidden items-center gap-1 rounded-full border border-success/20 bg-success-surface px-2 py-1 text-xs font-medium text-success sm:inline-flex"><CheckCircle2 aria-hidden="true" className="h-3.5 w-3.5"/>Ready</span>
              {multiple && <><Button aria-label={`Move ${file.name} up`} variant="ghost" size="icon" disabled={index === 0} onClick={() => move(index, -1)}><ArrowUp className="h-4 w-4" /></Button><Button aria-label={`Move ${file.name} down`} variant="ghost" size="icon" disabled={index === files.length - 1} onClick={() => move(index, 1)}><ArrowDown className="h-4 w-4" /></Button></>}
              <Button aria-label={`Remove ${file.name}`} variant="ghost" size="icon" onClick={() => setFiles((current) => current.filter((_, itemIndex) => itemIndex !== index))}><X className="h-4 w-4" /></Button>
            </li>)}</ul>}
            {pageInputTools.has(operation) && <label className="block text-sm font-medium">{operation === "organize-pdf" ? "New page order" : "Pages"}<Input className="mt-2" value={pages} onChange={(event) => setPages(event.target.value)} placeholder={operation === "organize-pdf" ? "3, 1, 2, 4-6" : "1-3, 5"} /></label>}
            {operation === "rotate-pdf" && <label className="block text-sm font-medium">Rotation<Input className="mt-2" type="number" min={90} max={270} step={90} value={rotation} onChange={(event) => setRotation(Number(event.target.value) as 90 | 180 | 270)} /></label>}
            {operation === "watermark-pdf" && <label className="block text-sm font-medium">Watermark text<Input className="mt-2" value={watermark} maxLength={80} onChange={(event) => setWatermark(event.target.value)} placeholder="Confidential" /></label>}
            {operation === "crop-pdf" && <fieldset><legend className="text-sm font-semibold">{isArabic ? "نسبة القص من كل حافة" : "Crop percentage from each edge"}</legend><p className="mt-1 text-xs leading-5 text-muted-foreground">{isArabic ? "يغيّر القص المساحة الظاهرة فقط؛ ولا يحذف المحتوى الموجود خارج CropBox ولا يُعد إخفاءً آمنًا للبيانات." : "Cropping changes the visible area only. It does not delete content outside the CropBox and is not secure redaction."}</p><div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">{(["topPercent", "rightPercent", "bottomPercent", "leftPercent"] as const).map((edge) => <label key={edge} className="text-sm font-medium">{{ topPercent: isArabic ? "أعلى" : "Top", rightPercent: isArabic ? "يمين" : "Right", bottomPercent: isArabic ? "أسفل" : "Bottom", leftPercent: isArabic ? "يسار" : "Left" }[edge]}<Input className="mt-2" type="number" min={0} max={45} step={1} value={crop[edge]} onChange={(event) => setCrop((current) => ({ ...current, [edge]: Number(event.target.value) }))} /></label>)}</div></fieldset>}
            {operation === "page-numbers" && <div className="grid gap-4 sm:grid-cols-2"><label className="text-sm font-medium">{isArabic ? "تنسيق الرقم" : "Number format"}<Input className="mt-2" value={numberFormat} maxLength={80} onChange={(event) => setNumberFormat(event.target.value)} aria-describedby="number-format-help" /></label><label className="text-sm font-medium">{isArabic ? "الموضع" : "Position"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={numberPosition} onChange={(event) => setNumberPosition(event.target.value)}>{["top-left", "top-center", "top-right", "bottom-left", "bottom-center", "bottom-right"].map((value) => <option key={value} value={value}>{value}</option>)}</select></label><p id="number-format-help" className="text-xs text-muted-foreground sm:col-span-2">{isArabic ? "استخدم {page} لرقم الصفحة و{total} للعدد الكلي." : "Use {page} for the page number and {total} for the total page count."}</p></div>}
            {operation === "header-footer" && <div className="grid gap-4"><label className="text-sm font-medium">{isArabic ? "نص الرأس" : "Header text"}<Input className="mt-2" dir="auto" value={headerText} maxLength={200} onChange={(event) => setHeaderText(event.target.value)} placeholder={isArabic ? "عنوان المستند" : "Document title"} /></label><label className="text-sm font-medium">{isArabic ? "نص التذييل" : "Footer text"}<Input className="mt-2" dir="auto" value={footerText} maxLength={200} onChange={(event) => setFooterText(event.target.value)} placeholder={isArabic ? "سري" : "Confidential"} /></label><label className="text-sm font-medium">{isArabic ? "المحاذاة" : "Alignment"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={alignment} onChange={(event) => setAlignment(event.target.value)}><option value="left">{isArabic ? "يسار" : "Left"}</option><option value="center">{isArabic ? "وسط" : "Center"}</option><option value="right">{isArabic ? "يمين" : "Right"}</option></select></label></div>}
            {operation === "resize-pages" && <div className="grid gap-4 sm:grid-cols-3"><label className="text-sm font-medium">{isArabic ? "حجم الصفحة" : "Page size"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={pageSize} onChange={(event) => setPageSize(event.target.value)}>{["a3", "a4", "letter", "legal"].map((value) => <option key={value} value={value}>{value.toUpperCase()}</option>)}</select></label><label className="text-sm font-medium">{isArabic ? "الاتجاه" : "Orientation"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={resizeOrientation} onChange={(event) => setResizeOrientation(event.target.value)}><option value="preserve">{isArabic ? "الحفاظ على الحالي" : "Preserve"}</option><option value="portrait">{isArabic ? "عمودي" : "Portrait"}</option><option value="landscape">{isArabic ? "أفقي" : "Landscape"}</option></select></label><label className="text-sm font-medium">{isArabic ? "ملاءمة المحتوى" : "Content fit"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={resizeFit} onChange={(event) => setResizeFit(event.target.value)}><option value="contain">{isArabic ? "احتواء دون تشويه" : "Contain"}</option><option value="stretch">{isArabic ? "تمديد إلى الصفحة" : "Stretch"}</option></select></label></div>}
            {operation === "alternate-mix" && <fieldset className="grid gap-4"><legend className="text-sm font-semibold">{isArabic ? "ترتيب التناوب" : "Alternating order"}</legend><p className="text-xs leading-5 text-muted-foreground">{isArabic ? "اختر ملفي PDF بالترتيب المطلوب. يمكن عكس الملف الثاني لدمج مسح الصفحات الفردية والزوجية." : "Choose exactly two PDFs in the required order. Reverse the second file when mixing separately scanned odd and even pages."}</p><label className="text-sm font-medium">{isArabic ? "ابدأ بـ" : "Start with"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={mixStart} onChange={(event) => setMixStart(event.target.value)}><option value="first">{isArabic ? "الملف الأول" : "First file"}</option><option value="second">{isArabic ? "الملف الثاني" : "Second file"}</option></select></label><label className="flex min-h-11 items-center gap-3 text-sm font-medium"><input className="h-4 w-4 accent-primary" type="checkbox" checked={reverseSecond} onChange={(event) => setReverseSecond(event.target.checked)} />{isArabic ? "عكس ترتيب صفحات الملف الثاني" : "Reverse the second PDF's page order"}</label></fieldset>}
            {operation === "flip-pages" && <div className="grid gap-4 sm:grid-cols-2"><label className="text-sm font-medium">{isArabic ? "محور القلب" : "Flip axis"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={flipAxis} onChange={(event) => setFlipAxis(event.target.value)}><option value="horizontal">{isArabic ? "أفقي" : "Horizontal"}</option><option value="vertical">{isArabic ? "رأسي" : "Vertical"}</option></select></label><label className="text-sm font-medium">{isArabic ? "الصفحات الاختيارية" : "Optional pages"}<Input className="mt-2" value={flipPageRange} maxLength={2000} onChange={(event) => setFlipPageRange(event.target.value)} placeholder={isArabic ? "مثال 1-3، 5؛ اتركه فارغًا للكل" : "e.g. 1-3, 5; blank means all"} /></label></div>}
            {operation === "split-pdf-by-size" && <label className="block text-sm font-medium">{isArabic ? "الحجم المستهدف لكل جزء (MB)" : "Target size per part (MB)"}<Input className="mt-2" type="number" min={1} max={100} step={1} value={targetSizeMb} onChange={(event) => setTargetSizeMb(Number(event.target.value))} /><span className="mt-1 block text-xs text-muted-foreground">{isArabic ? "الحجم تقريبي لأن تسلسل PDF وضغطه قد يغيّران عدد البايتات. قد تتجاوز صفحة واحدة الهدف." : "The target is approximate because PDF serialization and compression affect bytes. One page may exceed it."}</span></label>}
            {operation === "split-pdf-by-text" && <fieldset className="grid gap-4"><legend className="text-sm font-semibold">{isArabic ? "المطابقة الحرفية" : "Literal text match"}</legend><label className="text-sm font-medium">{isArabic ? "النص" : "Text"}<Input className="mt-2" dir="auto" value={matchText} maxLength={200} onChange={(event) => setMatchText(event.target.value)} /></label><label className="flex min-h-11 items-center gap-3 text-sm font-medium"><input className="h-4 w-4 accent-primary" type="checkbox" checked={caseSensitive} onChange={(event) => setCaseSensitive(event.target.checked)} />{isArabic ? "مطابقة حالة الأحرف الإنجليزية" : "Case-sensitive match"}</label><p className="text-xs text-muted-foreground">{isArabic ? "يبدأ جزء جديد قبل كل صفحة مطابقة. لا تُشغّل الأداة OCR تلقائيًا." : "A new part starts before each matching page. OCR is never invoked automatically."}</p></fieldset>}
            {operation === "split-pdf-by-bookmarks" && <p className="rounded-xl border bg-muted/30 p-4 text-sm text-muted-foreground">{isArabic ? "تُقبل فقط الوجهات الداخلية المباشرة. ترفض الأداة الوجهات الخارجية أو البعيدة أو غير الصالحة بدل التخمين." : "Only direct internal destinations are accepted. External, remote, named, or invalid destinations fail closed."}</p>}
            {operation === "n-up-pdf" && <div className="grid gap-4 sm:grid-cols-3"><label className="text-sm font-medium">{isArabic ? "الصفحات لكل ورقة" : "Pages per sheet"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={nUpLayout} onChange={(event) => setNUpLayout(Number(event.target.value))}>{[2,4,6,9].map((value) => <option key={value} value={value}>{value}</option>)}</select></label><label className="text-sm font-medium">{isArabic ? "اتجاه الورقة" : "Sheet orientation"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={nUpOrientation} onChange={(event) => setNUpOrientation(event.target.value)}><option value="portrait">{isArabic ? "عمودي" : "Portrait"}</option><option value="landscape">{isArabic ? "أفقي" : "Landscape"}</option></select></label><label className="text-sm font-medium">{isArabic ? "ترتيب الملء" : "Fill order"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={nUpOrder} onChange={(event) => setNUpOrder(event.target.value)}><option value="row">{isArabic ? "حسب الصف" : "Across rows"}</option><option value="column">{isArabic ? "حسب العمود" : "Down columns"}</option></select></label><p className="text-xs text-muted-foreground sm:col-span-3">{isArabic ? "يُركّب محتوى الصفحات بصريًا؛ لا تُحفظ الروابط والنماذج والتعليقات كعناصر تفاعلية." : "Page content is composed visually; links, forms, and annotations are not preserved as interactive objects."}</p></div>}
            {operation === "remove-annotations" && <fieldset className="grid gap-4"><legend className="text-sm font-semibold">{isArabic ? "سياسة الإزالة" : "Removal policy"}</legend><label className="text-sm font-medium">{isArabic ? "العناصر" : "Items"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={annotationPolicy} onChange={(event) => setAnnotationPolicy(event.target.value)}><option value="comments">{isArabic ? "التعليقات فقط" : "Comments only"}</option><option value="comments-and-links">{isArabic ? "التعليقات والروابط" : "Comments and links"}</option></select></label><p className="text-xs text-muted-foreground">{isArabic ? "تُحفظ عناصر النماذج widgets. تُرفض ملفات PDF الموقعة لأن إعادة الكتابة قد تبطل التوقيع." : "Form widgets are preserved. Signed PDFs are rejected because rewriting may invalidate signature integrity."}</p></fieldset>}
            {operation === "extract-images" && <p className="rounded-xl border bg-muted/30 p-4 text-sm text-muted-foreground">{isArabic ? "تستخرج الأداة كائنات الصور المضمنة المدعومة وتصدرها PNG بعد فكها بأمان. لا تُنشئ لقطات للصفحات، ولا تدّعي الحفاظ على البايتات الأصلية، وتوضح الأنواع غير المدعومة في تقرير النتيجة." : "This extracts supported embedded image objects as safely decoded PNG files. It never substitutes page screenshots, does not claim byte-identical originals, and reports unsupported objects."}</p>}
            {operation === "protect-pdf" && <fieldset className="grid gap-4"><legend className="text-sm font-semibold">{isArabic ? "تشفير AES-256" : "AES-256 encryption"}</legend><label className="text-sm font-medium">{isArabic ? "كلمة مرور المستخدم" : "User password"}<Input className="mt-2" type="password" autoComplete="new-password" maxLength={128} value={userPassword} onChange={(event) => setUserPassword(event.target.value)} /></label><label className="text-sm font-medium">{isArabic ? "كلمة مرور المالك" : "Owner password"}<Input className="mt-2" type="password" autoComplete="new-password" maxLength={128} value={ownerPassword} onChange={(event) => setOwnerPassword(event.target.value)} /></label><p className="text-xs text-muted-foreground">{isArabic ? "تُنقل كلمات المرور مؤقتًا بصورة مشفرة، وتُستهلك مرة واحدة، ولا تُحفظ في المهمة أو السجلات." : "Passwords use an encrypted, one-time, short-lived handoff and are never stored in job parameters or logs."}</p></fieldset>}
            {operation === "unlock-pdf" && <fieldset className="grid gap-4"><legend className="text-sm font-semibold">{isArabic ? "فك تشفير مصرح" : "Authorized decryption"}</legend><label className="text-sm font-medium">{isArabic ? "كلمة المرور الصحيحة" : "Valid PDF password"}<Input className="mt-2" type="password" autoComplete="current-password" maxLength={128} value={unlockPassword} onChange={(event) => setUnlockPassword(event.target.value)} /></label><label className="flex min-h-11 items-start gap-3 text-sm font-medium"><input className="mt-1 h-4 w-4 accent-primary" type="checkbox" checked={authorizedUse} onChange={(event) => setAuthorizedUse(event.target.checked)} />{isArabic ? "أؤكد أنني أملك الملف أو مخول بمعالجته وأنني أقدم كلمة مرور صحيحة. لا تنفذ الأداة تخمينًا أو كسرًا أو تجاوزًا للتشفير." : "I confirm that I own or am authorized to process this file and am providing a valid password. No guessing, cracking, brute force, or encryption bypass is performed."}</label></fieldset>}
            {operation === "pdf-permissions" && <fieldset className="grid gap-4"><legend className="text-sm font-semibold">{isArabic ? "قيود يفرضها برنامج العرض" : "Viewer-enforced permissions"}</legend><label className="text-sm font-medium">{isArabic ? "كلمة مرور المالك" : "Owner password"}<Input className="mt-2" type="password" autoComplete="new-password" maxLength={128} value={ownerPassword} onChange={(event) => setOwnerPassword(event.target.value)} /></label><label className="text-sm font-medium">{isArabic ? "كلمة مرور فتح اختيارية" : "Optional open password"}<Input className="mt-2" type="password" autoComplete="new-password" maxLength={128} value={userPassword} onChange={(event) => setUserPassword(event.target.value)} /></label><label className="text-sm font-medium">{isArabic ? "الطباعة" : "Printing"}<select className="mt-2 min-h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={permissions.printing} onChange={(event) => setPermissions((value) => ({ ...value, printing: event.target.value }))}><option value="full">{isArabic ? "كاملة" : "Full"}</option><option value="low">{isArabic ? "دقة منخفضة" : "Low resolution"}</option><option value="none">{isArabic ? "ممنوعة" : "None"}</option></select></label>{(["extraction", "assembly", "forms", "annotations"] as const).map((key) => <label key={key} className="flex min-h-11 items-center gap-3 text-sm font-medium"><input className="h-4 w-4 accent-primary" type="checkbox" checked={permissions[key]} onChange={(event) => setPermissions((value) => ({ ...value, [key]: event.target.checked }))} />{key}</label>)}<p className="text-xs text-muted-foreground">{isArabic ? "صلاحيات PDF قيود يطبقها برنامج العرض وليست DRM مطلقة. تظل إمكانية الوصول مفعلة." : "PDF permissions are viewer-enforced restrictions, not absolute DRM. Accessibility remains enabled."}</p></fieldset>}
            {operation === "repair-pdf" && <p className="rounded-xl border bg-muted/30 p-4 text-sm text-muted-foreground">{isArabic ? "تجرب الأداة استعادة بنيوية مضبوطة عبر qpdf ثم تعيد فتح الناتج. ترفض الملفات الموقعة أو المشفرة أو غير القابلة للإصلاح بدل إرجاع نجاح وهمي." : "A controlled qpdf recovery is attempted and the output is reopened. Signed, encrypted, and unrecoverable files are rejected instead of returning false success."}</p>}
            {(operation === "compress-pdf" || operation === "pdf-to-jpg") && <label className="block text-sm font-medium">Image quality: {Math.round(quality * 100)}%<input className="mt-3 block w-full accent-primary" type="range" min="0.45" max="0.95" step="0.05" value={quality} onChange={(event) => setQuality(Number(event.target.value))} /></label>}
            <Button className="min-h-12 w-full" size="lg" disabled={!files.length || status === "processing" || (operation === "merge-pdf" && files.length < 2) || (operation === "alternate-mix" && files.length !== 2) || (operation === "header-footer" && !headerText.trim() && !footerText.trim()) || (operation === "page-numbers" && !numberFormat.includes("{page}")) || (operation === "split-pdf-by-text" && !matchText.trim()) || (operation === "protect-pdf" && (!userPassword || !ownerPassword)) || (operation === "unlock-pdf" && (!unlockPassword || !authorizedUse)) || (operation === "pdf-permissions" && !ownerPassword)} onClick={process}>{status === "processing" ? (isArabic ? "جارٍ التنفيذ…" : "Processing…") : isArabic ? `معالجة ${files.length || ""} ملف` : `Process ${files.length || ""} file${files.length === 1 ? "" : "s"}`}</Button>
            {status === "processing" && <div className="dip-ai-card relative overflow-hidden rounded-2xl border border-info/30 bg-info-surface/35 p-5" data-streaming="true" role="status"><div aria-hidden="true" className="dip-laser"/><div className="relative flex items-center justify-between gap-4"><div><p className="font-semibold">{message}</p><p className="mt-1 text-xs text-muted-foreground">{progress.total > 0 ? `${progress.completed} / ${progress.total}` : "Worker active · progress updates live"}</p></div><span className="h-2.5 w-2.5 animate-ping rounded-full bg-info"/></div><Progress className="relative mt-4" label={`Processed ${progress.completed} of ${progress.total} pages`} value={progress.total > 0 ? (progress.completed / progress.total) * 100 : undefined} showLabel={progress.total > 0} /></div>}
            {message && <StatusFeedback status={status === "error" ? "error" : status === "done" ? "success" : "info"}>{message}</StatusFeedback>}
            {outputs.length > 0 && <div className="grid gap-2 sm:grid-cols-2">{outputs.map((output) => <Button key={output.name} variant="outline" onClick={() => downloadOutput(output)}><Download aria-hidden="true" className="h-4 w-4" />{output.name}</Button>)}</div>}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
