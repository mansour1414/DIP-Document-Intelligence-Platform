"use client";

import { useRef, useState } from "react";
import Link from "next/link";
import { Bot, FileText, LoaderCircle, Send, Sparkles, Upload, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { LanguageToggle, useLocale } from "@/components/i18n/locale-provider";
import type { ToolDefinition } from "@/config";

type Message = { role: "user" | "assistant"; content: string };

async function waitForAiJob(jobId: string) {
  for (let attempt = 0; attempt < 180; attempt += 1) {
    const response = await fetch(`/api/jobs/status/${jobId}`, { cache: "no-store" });
    const job = await response.json() as { status?: string; result?: { content?: string }; errorCode?: string; error?: { message?: string } };
    if (!response.ok) throw new Error(job.errorCode ?? "JOB_STATUS_FAILED");
    if (job.status === "succeeded" && job.result?.content) return job.result.content;
    if (["failed", "cancelled", "expired"].includes(job.status ?? "")) throw new Error(`${job.errorCode ?? "AI_JOB_FAILED"}: ${job.error?.message ?? "AI processing failed."}`);
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("AI_JOB_TIMEOUT: The job did not finish in time.");
}

export function AiToolWorkspace({ tool, embedded: _embedded = false }: { tool: ToolDefinition; embedded?: boolean }) {
  void _embedded;
  const { locale } = useLocale(); const ar = locale === "ar";
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [question, setQuestion] = useState(""); const [messages, setMessages] = useState<Message[]>([]);
  const [result, setResult] = useState(""); const [status, setStatus] = useState<"idle" | "reading" | "thinking" | "error">("idle"); const [notice, setNotice] = useState("");
  const chat = tool.id === "chat-with-pdf"; const extract = tool.id === "extract-data";
  const copy = ar ? { badge: "ذكاء DIP", drop: "اسحب ملف PDF أو اختره", limit: "حتى 100 ميجابايت و500 صفحة", read: "قراءة المستند…", think: "يجري تحليل المستند…", upload: "اختر ملف PDF أولاً", ask: "اسأل عن المستند", send: "إرسال", summary: "إنشاء ملخص", data: "استخراج البيانات", response: "نتيجة مولّدة بالذكاء الاصطناعي", noText: "لم يُعثر على نص قابل للقراءة. شغّل OCR للمستندات الممسوحة.", remove: "إزالة" } : { badge: "DIP AI", drop: "Drop a PDF or browse", limit: "Up to 100 MB and 500 pages", read: "Reading document…", think: "Analyzing document…", upload: "Choose a PDF first", ask: "Ask about the document", send: "Send", summary: "Create summary", data: "Extract data", response: "AI-generated result", noText: "No readable text was found. Run OCR for scanned documents.", remove: "Remove" };
  const select = async (candidate?: File) => {
    if (!candidate) return;
    if (!candidate.name.toLowerCase().endsWith(".pdf") && candidate.type !== "application/pdf") { setStatus("error"); setNotice("UNSUPPORTED_FILE: Choose a PDF file."); return; }
    if (candidate.size > 100 * 1024 * 1024) { setStatus("error"); setNotice("FILE_LIMIT: Choose a PDF no larger than 100 MB."); return; }
    setFile(candidate); setResult(""); setMessages([]); setStatus("idle"); setNotice("");
  };
  const run = async (currentQuestion?: string) => {
    if (!file) { setStatus("error"); setNotice(copy.upload); return; }
    const query = currentQuestion ?? question;
    if (chat && !query.trim()) return;
    window.dispatchEvent(new CustomEvent("dip:analytics", { detail: { name: "tool_started" } })); setStatus("thinking"); setNotice(copy.think); if (chat) { setMessages((current) => [...current, { role: "user", content: query }]); setQuestion(""); }
    try {
      const form = new FormData(); form.append("files", file); form.append("options", JSON.stringify({ question: query, locale }));
      const response = await fetch(`/api/jobs/${tool.id}`, { method: "POST", headers: { "Idempotency-Key": crypto.randomUUID(), "X-Correlation-Id": crypto.randomUUID() }, body: form });
      const payload = await response.json() as { jobId?: string; code?: string; message?: string };
      if (!response.ok || !payload.jobId) throw new Error(`${payload.code ?? "AI_ERROR"}: ${payload.message ?? "The AI job could not be queued."}`);
      const content = await waitForAiJob(payload.jobId);
      if (chat) setMessages((current) => [...current, { role: "assistant", content }]); else setResult(content);
      setStatus("idle"); setNotice(""); window.dispatchEvent(new CustomEvent("dip:analytics", { detail: { name: "tool_completed" } }));
    } catch (error) { setStatus("error"); setNotice(error instanceof Error ? error.message : "AI_ERROR"); window.dispatchEvent(new CustomEvent("dip:analytics", { detail: { name: "tool_failed", error_code: "AI_ERROR" } })); }
  };
  return <main className="min-h-screen bg-slate-50 text-slate-950"><header className="border-b border-slate-200 bg-white"><div className="mx-auto flex h-16 max-w-5xl items-center gap-3 px-4 sm:px-6"><Link href="/" className="rounded-lg bg-blue-700 px-2.5 py-1.5 text-sm font-bold text-white">DIP</Link><span aria-hidden="true" className="text-slate-300">/</span><span className="flex-1 font-semibold">{ar ? tool.nameAr : tool.name}</span><LanguageToggle /></div></header><div className="mx-auto max-w-3xl px-4 py-10 sm:px-6"><div className="mb-7"><div className="mb-3 inline-flex items-center gap-2 rounded-full bg-violet-50 px-3 py-1 text-sm font-medium text-violet-800"><Sparkles aria-hidden="true" className="h-4 w-4" />{copy.badge}</div><h1 className="text-3xl font-bold tracking-tight sm:text-4xl">{ar ? tool.nameAr : tool.name}</h1><p className="mt-3 text-slate-600">{ar ? tool.descriptionAr : tool.description}. {ar ? "تتم المعالجة داخل عامل DIP ويُرسل النص المحدد فقط عبر بوابة الذكاء الاصطناعي." : "Processing runs in the DIP worker and only scoped text passes through the AI gateway."}</p></div><Card><CardHeader><CardTitle>{file ? file.name : copy.drop}</CardTitle></CardHeader><CardContent className="space-y-5"><button type="button" onClick={() => fileRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); void select(event.dataTransfer.files.item(0) ?? undefined); }} className="flex min-h-36 w-full flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-300 bg-slate-50 px-6 text-center hover:border-blue-500 hover:bg-blue-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-600"><Upload aria-hidden="true" className="mb-3 h-8 w-8 text-blue-700" /><span className="font-semibold">{copy.drop}</span><span className="mt-1 text-sm text-slate-600">{copy.limit}</span></button><input ref={fileRef} className="sr-only" type="file" accept=".pdf,application/pdf" onChange={(event) => void select(event.target.files?.[0])} />{file && <div className="flex items-center gap-3 rounded-lg border border-slate-200 p-3"><FileText aria-hidden="true" className="h-5 w-5 text-red-600" /><span className="min-w-0 flex-1 truncate text-sm font-medium">{file.name}</span><Button variant="ghost" size="icon" aria-label={`${copy.remove} ${file.name}`} onClick={() => { setFile(null); setResult(""); setMessages([]); }}><X className="h-4 w-4" /></Button></div>}{chat ? <><div className="max-h-96 space-y-3 overflow-y-auto rounded-xl bg-slate-100 p-4" aria-live="polite">{messages.length === 0 && <p className="text-sm text-slate-600">{ar ? "حمّل مستنداً ثم اكتب سؤالك." : "Upload a document, then ask a question."}</p>}{messages.map((message, index) => <div key={index} className={`rounded-lg p-3 text-sm whitespace-pre-wrap ${message.role === "user" ? "bg-blue-700 text-white" : "bg-white text-slate-800"}`}><strong>{message.role === "assistant" ? "DIP AI" : ar ? "أنت" : "You"}</strong><p className="mt-1">{message.content}</p></div>)}</div><div className="flex gap-2"><Input value={question} onChange={(event) => setQuestion(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void run(); }} placeholder={copy.ask} disabled={!file || status !== "idle"} /><Button aria-label={copy.send} disabled={!file || !question.trim() || status !== "idle"} onClick={() => void run()}><Send aria-hidden="true" className="h-4 w-4" />{copy.send}</Button></div></> : <><Button className="min-h-12 w-full" size="lg" disabled={!file || status !== "idle"} onClick={() => void run()}>{status === "thinking" ? <LoaderCircle aria-hidden="true" className="animate-spin" /> : <Bot aria-hidden="true" />} {extract ? copy.data : copy.summary}</Button>{result && <section aria-label={copy.response} className="rounded-xl border border-violet-200 bg-violet-50 p-5"><p className="mb-3 text-sm font-semibold text-violet-900">{copy.response}</p><div className="whitespace-pre-wrap text-sm leading-7 text-slate-800">{result}</div></section>}</>}{(status === "reading" || status === "thinking") && <div role="status" className="rounded-lg bg-blue-50 px-4 py-3 text-sm text-blue-800">{notice}</div>}{status === "error" && <div role="alert" className="rounded-lg bg-red-50 px-4 py-3 text-sm text-red-800">{notice}</div>}</CardContent></Card></div></main>;
}
