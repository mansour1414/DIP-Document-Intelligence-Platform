import type { Metadata } from "next";
import { notFound, redirect } from "next/navigation";
import { currentUser } from "@/lib/auth/user";
import { withTenant } from "@/lib/db/tenant";
import { SiteHeader } from "@/components/seo/site-header";
import { AgentWorkspace } from "@/components/agent/agent-workspace";
export const metadata: Metadata = { robots: { index: false, follow: false } };
export default async function AgentPage({ params }: { params: Promise<{ locale: string }> }) { const { locale } = await params; if (locale !== "en" && locale !== "ar") notFound(); const user = await currentUser(); if (!user) redirect(`/${locale}/login`); const files = await withTenant({ userId: user.id }, (tx) => tx.file.findMany({ where: { document: { userId: user.id, status: "ACTIVE" } }, select: { id: true, originalName: true, mimeType: true }, orderBy: { createdAt: "desc" }, take: 50 })); return <><SiteHeader locale={locale}/><AgentWorkspace locale={locale} files={files}/></>; }
