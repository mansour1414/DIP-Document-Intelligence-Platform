import type { Metadata } from "next";
import { notFound, redirect } from "next/navigation";
import { currentUser } from "@/lib/auth/user";
import { withTenant } from "@/lib/db/tenant";
import { listWorkflows } from "@/lib/workflows/service";
import { toolRegistry, workerToolIds } from "@/lib/tools/registry";
import { WorkflowManager } from "@/components/workflows/workflow-manager";
export const metadata: Metadata = { robots: { index: false, follow: false } };
export default async function WorkflowsPage({ params }: { params: Promise<{ locale: string }> }) { const { locale } = await params; if (!["en", "ar"].includes(locale)) notFound(); const user = await currentUser(); if (!user) redirect("/login"); const [workflows, files] = await Promise.all([listWorkflows(user.id), withTenant({ userId: user.id }, (tx) => tx.file.findMany({ where: { document: { userId: user.id, status: "ACTIVE" } }, select: { id: true, originalName: true, mimeType: true }, orderBy: { createdAt: "desc" }, take: 50 }))]); const tools = Object.values(toolRegistry).filter((tool) => workerToolIds.has(tool.toolId)).map((tool) => ({ toolId: tool.toolId, name: tool.name, version: tool.version })); return <WorkflowManager locale={locale as "en" | "ar"} tools={tools} files={files} initialWorkflows={workflows as never} />; }
