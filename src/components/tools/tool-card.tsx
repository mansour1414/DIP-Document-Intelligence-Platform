import Link from "next/link";
import { ArrowUpRight, Sparkles } from "lucide-react";
import type { Locale, MvpToolId } from "@/lib/seo/tool-content";
import { getTool } from "@/config";
import { Badge } from "@/components/ui/badge";
import { toolIcons } from "./tool-catalog";

export function ToolCard({ toolId, locale }: { toolId: MvpToolId; locale: Locale }) {
  const tool = getTool(toolId)!;
  const ar = locale === "ar";
  const Icon = toolIcons[toolId];
  return <Link href={`/${locale}/tools/${toolId}`} className="dip-glass dip-sweep group flex min-h-44 flex-col rounded-2xl p-5 text-card-foreground transition-[border-color,box-shadow,transform] duration-200 hover:-translate-y-1 hover:border-info/35 hover:shadow-[0_0_36px_-14px_rgb(6_182_212/.5)] focus-visible:ring-2 focus-visible:ring-ring"><div className="flex items-start justify-between gap-3"><span className="grid h-11 w-11 place-items-center rounded-xl border border-info/20 bg-gradient-to-br from-primary/15 to-info/10 text-primary transition-colors group-hover:text-info"><Icon aria-hidden="true" className="h-6 w-6" /></span><span className="flex gap-1">{tool.execution === "ai" && <Badge variant="info"><Sparkles aria-hidden="true" className="h-3 w-3" />AI</Badge>}{toolId === "pdf-to-word" && <Badge>Beta</Badge>}</span></div><h3 className="mt-4 font-bold">{ar ? tool.nameAr : tool.name}</h3><p className="mt-1 line-clamp-2 text-sm leading-6 text-muted-foreground">{ar ? tool.descriptionAr : tool.description}</p><ArrowUpRight aria-hidden="true" className="mt-auto h-4 w-4 self-end text-muted-foreground transition-[color,transform] group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-info rtl:-scale-x-100" /></Link>;
}
