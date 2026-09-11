"use client";
import { useState } from "react";
import type { Locale, MvpToolId } from "@/lib/seo/tool-content";
import { mvpToolIds } from "@/lib/seo/tool-content";
import { Button } from "@/components/ui/button";
import { ToolCard } from "./tool-card";
import { toolGroups, type ToolGroupId } from "./tool-catalog";
export function ToolGrid({ locale }: { locale: Locale }) { const ar = locale === "ar"; const [active, setActive] = useState<ToolGroupId>("all"); const ids: readonly MvpToolId[] = active === "all" ? mvpToolIds : toolGroups.find((group) => group.id === active)!.tools; return <><div role="toolbar" aria-label={ar ? "تصفية الأدوات" : "Filter tools"} className="mb-6 flex gap-2 overflow-x-auto pb-2"><Button size="sm" variant={active === "all" ? "default" : "outline"} onClick={() => setActive("all")} aria-pressed={active === "all"}>{ar ? "الجميع" : "All"}</Button>{toolGroups.map((group) => <Button key={group.id} size="sm" variant={active === group.id ? "default" : "outline"} onClick={() => setActive(group.id)} aria-pressed={active === group.id}>{ar ? group.ar : group.en}</Button>)}</div><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">{ids.map((id) => <ToolCard key={id} toolId={id} locale={locale} />)}</div></>; }
