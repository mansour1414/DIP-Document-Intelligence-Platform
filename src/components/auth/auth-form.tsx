"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { BrandMark } from "@/components/brand/brand-mark";
import { StatusFeedback } from "@/components/ui/status-feedback";

export function AuthForm({ mode }: { mode: "signin" | "signup" }) {
  const router = useRouter();
  const [email, setEmail] = useState(""); const [password, setPassword] = useState(""); const [name, setName] = useState(""); const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  const signup = mode === "signup";
  const submit = async (event: React.FormEvent) => { event.preventDefault(); setBusy(true); setError(""); try { const response = await fetch(`/api/auth/${mode}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password, displayName: name }) }); const body = await response.json(); if (!response.ok) throw new Error(body.message); router.push("/dashboard"); router.refresh(); } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to continue."); } finally { setBusy(false); } };
  return <main className="relative grid min-h-screen place-items-center overflow-hidden bg-muted/40 p-4"><div aria-hidden="true" className="dip-grid-pattern absolute inset-0"/><form onSubmit={submit} className="relative w-full max-w-md space-y-5 rounded-2xl border bg-card p-6 text-card-foreground shadow-elevated sm:p-8"><BrandMark /><div><h1 className="text-2xl font-bold tracking-tight">{signup ? "Create your account" : "Welcome back"}</h1><p className="mt-1 text-sm leading-6 text-muted-foreground">{signup ? "Start with 20 free processing credits." : "Sign in to access your documents and credits."}</p></div>{signup && <label className="block text-sm font-medium">Name<Input className="mt-2" value={name} onChange={(event) => setName(event.target.value)} autoComplete="name" /></label>}<label className="block text-sm font-medium">Email<Input className="mt-2" type="email" required value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" /></label><label className="block text-sm font-medium">Password<Input className="mt-2" type="password" required minLength={10} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete={signup ? "new-password" : "current-password"} /></label>{error && <StatusFeedback status="error">{error}</StatusFeedback>}<Button className="w-full" size="lg" disabled={busy}>{busy ? "Please wait…" : signup ? "Create account" : "Sign in"}</Button><Button asChild variant="outline" className="w-full"><Link href="/api/auth/oauth/github">Continue with GitHub</Link></Button><p className="text-center text-sm text-muted-foreground">{signup ? "Already have an account?" : "Need an account?"} <Link className="font-semibold text-primary hover:underline" href={signup ? "/login" : "/signup"}>{signup ? "Sign in" : "Create one"}</Link></p></form></main>;
}
