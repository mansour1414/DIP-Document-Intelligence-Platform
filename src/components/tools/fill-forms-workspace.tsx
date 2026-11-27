"use client";

import { useEffect, useRef, useState } from "react";
import { Download, FileText, Lock, TextCursorInput, TriangleAlert, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { LanguageToggle, useLocale } from "@/components/i18n/locale-provider";
import { Progress } from "@/components/ui/progress";
import { StatusFeedback } from "@/components/ui/status-feedback";
import { UploadZone } from "@/components/ui/upload-zone";
import { BrandMark } from "@/components/brand/brand-mark";
import type { ToolDefinition } from "@/config";
import type { FormFieldDescriptor, FormFillValue, FormInventory } from "@/lib/pdf/form-types";
import { FormFillError, parseFieldsPayload, validateFillValues } from "@/lib/pdf/form-validation";
import { FormInspectionError, inspectFillForm } from "@/lib/client/form-inspection";
import {
  ServerToolJobError,
  createRunGuard,
  downloadServerToolOutputWithRetry,
  formatJobError,
  idempotencyFor,
  pollJobOutput,
  retainsIdempotencyKey,
  submitServerToolJob,
  type PendingSubmission,
} from "@/lib/client/server-tool-job";

type Phase = "idle" | "inspecting" | "editing" | "processing" | "waiting" | "output-retry" | "done" | "error";

/** Values as the user edits them; converted to the transport payload on submit. */
type Draft = Record<string, string | boolean | string[]>;

function initialDraft(inventory: FormInventory): Draft {
  const draft: Draft = {};
  for (const field of inventory.fields) {
    if (field.readOnly) continue;
    if (field.kind === "checkbox") draft[field.name] = field.value === true;
    else if (field.kind === "optionlist") draft[field.name] = Array.isArray(field.value) ? field.value : [];
    else draft[field.name] = typeof field.value === "string" ? field.value : "";
  }
  return draft;
}

/**
 * Only *changed* values are submitted, so the untouched-field guarantee is not
 * merely tested on the server — it is what the request asks for. A field left at
 * its current value is never named, and the worker proves it kept its value.
 */
function changedValues(inventory: FormInventory, draft: Draft): Record<string, FormFillValue> {
  const values: Record<string, FormFillValue> = {};
  for (const field of inventory.fields) {
    if (field.readOnly || !(field.name in draft)) continue;
    const next = draft[field.name];
    const previous = field.value ?? (field.kind === "checkbox" ? false : field.kind === "optionlist" ? [] : null);
    const normalizedNext = field.kind === "text" && next === "" && previous === null ? null : next;
    if (JSON.stringify(normalizedNext) !== JSON.stringify(previous)) values[field.name] = next;
  }
  return values;
}

export function FillFormsWorkspace({ tool, embedded: _embedded = false }: { tool: ToolDefinition; embedded?: boolean }) {
  void _embedded;
  const { locale } = useLocale();
  const isArabic = locale === "ar";
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [inventory, setInventory] = useState<FormInventory | null>(null);
  const [draft, setDraft] = useState<Draft>({});
  const [flatten, setFlatten] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [message, setMessage] = useState("");
  const [output, setOutput] = useState<{ url: string; name: string } | null>(null);
  const [pendingJobId, setPendingJobId] = useState<string | null>(null);
  const [completedOutputFileId, setCompletedOutputFileId] = useState<string | null>(null);

  const copy = isArabic
    ? { badge: "تعبئة نماذج أكرو فورم في معالج معزول", upload: "حمّل نموذج PDF يحتوي حقولاً قابلة للتعبئة", drop: "اسحب نموذجاً هنا أو اختره", limit: "ملف PDF واحد، حتى 100 ميجابايت", inspecting: "يُقرأ النموذج…", fields: "الحقول", unsupported: "حقول غير مدعومة", flatten: "تثبيت القيم (إزالة التفاعل بعد التعبئة)", fill: "تعبئة النموذج", empty: "لا توجد تغييرات لإرسالها. عدّل حقلاً واحداً على الأقل.", ready: "أصبح النموذج المعبأ جاهزاً ويمكن تنزيله.", queued: "تم إدراج النموذج، ويجري تعبئته في العامل المعزول…", waiting: "قد تستغرق المعالجة لحظات. يمكنك التحقق من الحالة دون إنشاء مهمة جديدة.", checkAgain: "التحقق من الحالة", stillRunning: "ما زال العامل يعالج النموذج؛ لن تُنشأ مهمة جديدة.", outputRetry: "اكتملت المعالجة لكن تعذّر تنزيل النتيجة؛ يمكنك إعادة المحاولة دون إعادة التعبئة.", retryDownload: "إعادة محاولة التنزيل", processing: "تتم المعالجة بأمان…", download: "تحميل", remove: "إزالة", removeBusy: "لا يمكن إزالة الملف أثناء المعالجة.", readonly: "للقراءة فقط", page: "صفحة", rejected: "تم رفض النموذج", reserved: "يُحتفظ بالقيم المحسوبة في العامل؛ ولا تُكتب أي قيمة غير متحققة." }
    : { badge: "AcroForm filling on an isolated worker", upload: "Upload a PDF with fillable fields", drop: "Drop a form here or browse", limit: "One PDF, up to 100 MB", inspecting: "Reading the form…", fields: "Fields", unsupported: "Unsupported fields", flatten: "Flatten values (remove interactivity after filling)", fill: "Fill form", empty: "Nothing to submit yet — change at least one field.", ready: "Your filled form is ready to download.", queued: "Form queued; the isolated worker is filling it…", waiting: "Processing may take a moment. You can check the status without creating a new job.", checkAgain: "Check status", stillRunning: "The worker is still filling this form; no new job will be created.", outputRetry: "Processing finished but the output could not be downloaded. Retrying will not re-run the fill.", retryDownload: "Retry download", processing: "Processing securely…", download: "Download", remove: "Remove", removeBusy: "The file cannot be removed while processing.", readonly: "read-only", page: "page", rejected: "This form was rejected", reserved: "Values are computed on the worker; nothing unverified is ever written." };

  const guardRef = useRef<ReturnType<typeof createRunGuard> | null>(null);
  guardRef.current ??= createRunGuard();
  const pendingSubmissionRef = useRef<PendingSubmission | null>(null);
  const selectionTokenRef = useRef<string | null>(null);
  const outputUrlRef = useRef<string | null>(null);
  const inspectAbortRef = useRef<AbortController | null>(null);

  const releaseOutputUrl = () => {
    if (outputUrlRef.current) { URL.revokeObjectURL(outputUrlRef.current); outputUrlRef.current = null; }
  };
  const clearOutput = () => { releaseOutputUrl(); setOutput(null); };
  useEffect(() => () => { guardRef.current?.cancel(); inspectAbortRef.current?.abort(); releaseOutputUrl(); }, []);

  const busy = phase === "processing" || phase === "inspecting";
  const pending = phase === "processing" || phase === "waiting";

  const select = async (candidate?: File) => {
    if (!candidate || busy) return;
    if (candidate.size > tool.limits.maxBytes) { setPhase("error"); setMessage("FILE_LIMIT: Choose a PDF no larger than 100 MB."); return; }
    guardRef.current?.cancel();
    inspectAbortRef.current?.abort();
    pendingSubmissionRef.current = null; setPendingJobId(null); setCompletedOutputFileId(null);
    selectionTokenRef.current = globalThis.crypto.randomUUID();
    clearOutput(); setFile(candidate); setInventory(null); setDraft({}); setMessage(""); setPhase("inspecting");
    const controller = new AbortController();
    inspectAbortRef.current = controller;
    try {
      const found = await inspectFillForm({ file: candidate, signal: controller.signal });
      if (controller.signal.aborted) return;
      setInventory(found); setDraft(initialDraft(found)); setPhase("editing");
    } catch (error) {
      if (controller.signal.aborted) return;
      setPhase("error");
      setMessage(error instanceof FormInspectionError ? `${error.code}: ${error.message}` : "The form could not be inspected.");
    }
  };

  const removeFile = () => {
    if (busy) return;
    guardRef.current?.cancel();
    inspectAbortRef.current?.abort();
    pendingSubmissionRef.current = null; setPendingJobId(null); setCompletedOutputFileId(null);
    selectionTokenRef.current = null;
    clearOutput(); setFile(null); setInventory(null); setDraft({}); setPhase("idle"); setMessage("");
  };

  const finish = (run: number, next: Phase, text: string) => {
    if (!guardRef.current?.isCurrent(run)) return;
    guardRef.current?.finish(run);
    setPhase(next); setMessage(text);
  };

  const deliverOutput = async (run: number, fileId: string) => {
    try {
      const download = await downloadServerToolOutputWithRetry({ fileId, fallbackName: "filled-form.pdf" });
      if (!guardRef.current?.isCurrent(run)) return;
      releaseOutputUrl();
      outputUrlRef.current = URL.createObjectURL(download.blob);
      setOutput({ url: outputUrlRef.current, name: download.filename });
      setCompletedOutputFileId(null); setPendingJobId(null); pendingSubmissionRef.current = null;
      finish(run, "done", copy.ready);
    } catch (error) {
      if (!guardRef.current?.isCurrent(run)) return;
      setCompletedOutputFileId(fileId);
      finish(run, "output-retry", `${copy.outputRetry} ${formatJobError(error)}`);
    }
  };

  const runPolling = async (run: number, jobId: string) => {
    setPendingJobId(jobId);
    try {
      const result = await pollJobOutput({ jobId, isOcr: false });
      if (!guardRef.current?.isCurrent(run)) return;
      await deliverOutput(run, result.fileId);
    } catch (error) {
      if (!guardRef.current?.isCurrent(run)) return;
      if (error instanceof ServerToolJobError && error.code === "STILL_PROCESSING") { finish(run, "waiting", copy.stillRunning); return; }
      setPendingJobId(null);
      if (!retainsIdempotencyKey(error)) pendingSubmissionRef.current = null;
      finish(run, "error", formatJobError(error));
    }
  };

  const submit = async () => {
    if (!file || !inventory || guardRef.current?.busy()) return;
    let values: Record<string, FormFillValue>;
    try {
      values = parseFieldsPayload(changedValues(inventory, draft));
      // Same validator the worker runs, so anything rejected here would be
      // rejected there for the same reason — before a job is queued.
      validateFillValues(inventory, values);
    } catch (error) {
      setPhase("error");
      setMessage(error instanceof FormFillError ? `${error.code}: ${error.message}` : copy.empty);
      return;
    }
    const run = guardRef.current?.start() ?? -1;
    if (run < 0) return;
    selectionTokenRef.current ??= globalThis.crypto.randomUUID();
    const options = { flatten };
    const request = { toolId: tool.id, options, fields: values, file, selectionToken: selectionTokenRef.current };
    const key = idempotencyFor(pendingSubmissionRef.current, request);
    pendingSubmissionRef.current = key;
    setPhase("processing"); setMessage(copy.queued);
    try {
      const submission = await submitServerToolJob({ toolId: request.toolId, options: request.options, fields: request.fields, file: request.file, idempotencyKey: key.key, correlationId: globalThis.crypto.randomUUID() });
      if (!guardRef.current?.isCurrent(run)) return;
      await runPolling(run, submission.jobId);
    } catch (error) {
      if (!guardRef.current?.isCurrent(run)) return;
      setPendingJobId(null);
      if (!retainsIdempotencyKey(error)) pendingSubmissionRef.current = null;
      finish(run, "error", formatJobError(error));
    }
  };

  const checkAgain = async () => {
    const jobId = pendingJobId;
    if (!jobId || guardRef.current?.busy()) return;
    const run = guardRef.current?.start() ?? -1;
    if (run < 0) return;
    setPhase("processing");
    await runPolling(run, jobId);
  };

  const retryDownload = async () => {
    const fileId = completedOutputFileId;
    if (!fileId || guardRef.current?.busy()) return;
    const run = guardRef.current?.start() ?? -1;
    if (run < 0) return;
    setPhase("processing");
    await deliverOutput(run, fileId);
  };

  const update = (name: string, value: FormFillValue) => setDraft((current) => ({ ...current, [name]: value }));

  const field = (item: FormFieldDescriptor) => {
    const value = draft[item.name];
    const disabled = item.readOnly || busy;
    if (item.kind === "checkbox") {
      return <label key={item.name} className="flex min-h-11 items-center gap-3 text-sm"><Checkbox checked={value === true} disabled={disabled} onChange={(event) => update(item.name, event.target.checked)} /><span className="font-medium">{item.name}</span></label>;
    }
    if (item.kind === "dropdown" || item.kind === "radio") {
      return (
        <label key={item.name} className="block text-sm">
          <span className="mb-1.5 block font-medium">{item.name}</span>
          <Select value={typeof value === "string" ? value : ""} disabled={disabled} onChange={(event) => update(item.name, event.target.value)}>
            <option value="">—</option>
            {(item.options ?? []).map((option) => <option key={option} value={option}>{option}</option>)}
          </Select>
        </label>
      );
    }
    if (item.kind === "optionlist") {
      const selected = Array.isArray(value) ? value : [];
      return (
        <fieldset key={item.name} className="rounded-xl border bg-muted/25 p-3">
          <legend className="px-1 text-sm font-medium">{item.name}</legend>
          <div className="mt-1 flex flex-wrap gap-x-4 gap-y-2">
            {(item.options ?? []).map((option) => (
              <label key={option} className="flex min-h-9 items-center gap-2 text-sm">
                <Checkbox checked={selected.includes(option)} disabled={disabled} onChange={(event) => update(item.name, event.target.checked ? [...selected, option] : selected.filter((entry) => entry !== option))} />
                {option}
              </label>
            ))}
          </div>
        </fieldset>
      );
    }
    const text = typeof value === "string" ? value : "";
    return (
      <label key={item.name} className="block text-sm">
        <span className="mb-1.5 block font-medium">{item.name}{item.maxLength ? <span className="ms-1 text-xs font-normal text-muted-foreground">({text.length}/{item.maxLength})</span> : null}</span>
        {item.multiline
          ? <Textarea value={text} disabled={disabled} maxLength={item.maxLength} onChange={(event) => update(item.name, event.target.value)} />
          : <Input value={text} disabled={disabled} maxLength={item.maxLength} onChange={(event) => update(item.name, event.target.value)} />}
      </label>
    );
  };

  const hasChanges = inventory ? Object.keys(changedValues(inventory, draft)).length > 0 : false;

  return (
    <main className="min-h-screen bg-muted/35 text-foreground">
      <header className="border-b bg-card"><div className="mx-auto flex min-h-16 max-w-5xl items-center gap-3 px-4 sm:px-6"><BrandMark href="/" /><span aria-hidden="true" className="text-border">/</span><span className="flex-1 font-semibold">{isArabic ? tool.nameAr : tool.name}</span><LanguageToggle /></div></header>
      <div className="mx-auto max-w-3xl px-4 py-10 sm:px-6">
        <div className="mb-7">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full bg-secondary px-3 py-1 text-sm font-semibold text-secondary-foreground"><Lock aria-hidden="true" className="h-4 w-4" />{copy.badge}</div>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">{isArabic ? tool.nameAr : tool.name}</h1>
          <p className="mt-3 max-w-2xl text-base leading-7 text-muted-foreground">{isArabic ? tool.descriptionAr : tool.description}</p>
        </div>
        <Card>
          <CardHeader><CardTitle>{copy.upload}</CardTitle></CardHeader>
          <CardContent className="space-y-6">
            <UploadZone title={copy.drop} description={copy.limit} hint={isArabic ? "يُرفض الموقّع والمشفّر والـ XFA" : "Signed, encrypted and XFA files are rejected"} invalid={phase === "error" && !file} disabled={busy} onClick={() => inputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); void select(event.dataTransfer.files.item(0) ?? undefined); }} />
            <input ref={inputRef} className="sr-only" type="file" accept=".pdf,application/pdf" disabled={busy} onChange={(event) => void select(event.target.files?.[0])} />
            {file && <div className="flex min-h-14 items-center gap-3 rounded-xl border bg-card px-3 shadow-sm"><FileText aria-hidden="true" className="h-5 w-5 shrink-0 text-primary" /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{file.name}</p><p className="text-xs text-muted-foreground">{(file.size / 1024 / 1024).toFixed(2)} MB</p></div><Button aria-label={`${copy.remove} ${file.name}`} title={busy ? copy.removeBusy : copy.remove} disabled={busy} variant="ghost" size="icon" onClick={removeFile}><X className="h-4 w-4" /></Button></div>}
            {phase === "inspecting" && <div role="status"><Progress label={copy.inspecting} /></div>}
            {inventory && (
              <section aria-labelledby="fill-forms-fields">
                <h2 id="fill-forms-fields" className="mb-3 flex items-center gap-2 text-sm font-semibold"><TextCursorInput aria-hidden="true" className="h-4 w-4 text-primary" />{copy.fields} ({inventory.fields.length}) · {inventory.pages} {copy.page}</h2>
                <div className="space-y-3">{inventory.fields.map(field)}</div>
                {inventory.unsupported.length > 0 && (
                  <div className="mt-4 rounded-xl border border-warning/40 bg-warning-surface/40 p-3 text-sm">
                    <p className="flex items-center gap-2 font-semibold"><TriangleAlert aria-hidden="true" className="h-4 w-4" />{copy.unsupported} ({inventory.unsupported.length})</p>
                    <ul className="mt-1 list-disc ps-6 text-muted-foreground">{inventory.unsupported.slice(0, 20).map((item) => <li key={item.name}>{item.name}: {item.reason}</li>)}</ul>
                  </div>
                )}
                <label className="mt-4 flex min-h-11 items-center gap-2 text-sm"><Checkbox checked={flatten} disabled={busy} onChange={(event) => setFlatten(event.target.checked)} />{copy.flatten}</label>
              </section>
            )}
            {phase !== "waiting" && phase !== "output-retry" && <Button className="min-h-12 w-full" size="lg" disabled={!file || !inventory || busy || !hasChanges} onClick={submit}>{busy ? copy.processing : copy.fill}</Button>}
            {pending && <div className="dip-ai-card relative overflow-hidden rounded-2xl border border-info/30 bg-info-surface/35 p-5" data-streaming="true" role="status"><div aria-hidden="true" className="dip-laser" /><p className="relative font-semibold">{copy.processing}</p><p className="relative mt-1 text-sm text-muted-foreground">{copy.waiting}</p><Progress className="relative mt-4" label={copy.waiting} /></div>}
            {message && <StatusFeedback status={phase === "error" ? "error" : phase === "done" ? "success" : "info"}>{message}</StatusFeedback>}
            {phase === "waiting" && <Button className="min-h-12 w-full" size="lg" variant="outline" disabled={!pendingJobId} onClick={checkAgain}>{copy.checkAgain}</Button>}
            {phase === "output-retry" && <Button className="min-h-12 w-full" size="lg" variant="outline" disabled={!completedOutputFileId} onClick={retryDownload}>{copy.retryDownload}</Button>}
            {output && <Button className="w-full" variant="outline" asChild><a href={output.url} download={output.name}><Download aria-hidden="true" className="h-4 w-4" />{copy.download} {output.name}</a></Button>}
          </CardContent>
        </Card>
        <p className="mt-4 text-xs text-muted-foreground">{copy.reserved}</p>
      </div>
    </main>
  );
}
