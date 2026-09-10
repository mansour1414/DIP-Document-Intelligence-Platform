"use client";
import { useEffect, useRef } from "react";
import { track } from "@/lib/analytics";

export function ToolPageAnalytics({ toolId, locale }: { toolId: string; locale: "en" | "ar" }) {
  const startedAt = useRef<number | null>(null);
  useEffect(() => { track({ name: "tool_page_view", tool_id: toolId, language: locale, page_path: window.location.pathname, source: document.referrer ? "internal" : "direct" }); }, [locale, toolId]);
  useEffect(() => {
    const listener = (event: Event) => {
      const detail = (event as CustomEvent<{ name: "tool_started" | "tool_completed" | "tool_failed"; error_code?: string }>).detail;
      if (!detail?.name) return;
      if (detail.name === "tool_started") startedAt.current = performance.now();
      track({ name: detail.name, tool_id: toolId, language: locale, page_path: window.location.pathname, duration_ms: startedAt.current && detail.name !== "tool_started" ? Math.round(performance.now() - startedAt.current) : undefined, error_code: detail.error_code });
    };
    window.addEventListener("dip:analytics", listener); return () => window.removeEventListener("dip:analytics", listener);
  }, [locale, toolId]);
  return null;
}

