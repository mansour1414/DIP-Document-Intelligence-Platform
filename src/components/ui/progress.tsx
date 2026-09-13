"use client";
import { useEffect } from "react";
import { motion, useSpring, useTransform } from "motion/react";
import { cn } from "@/lib/utils";

export function Progress({ value, className, label, showLabel = false }: { value?: number; className?: string; label?: string; showLabel?: boolean }) {
  const normalized = value === undefined ? undefined : Math.max(0, Math.min(100, value));
  const spring = useSpring(normalized ?? 0, { stiffness: 100, damping: 15, mass: 1 });
  const width = useTransform(spring, (current) => `${current}%`);
  useEffect(() => { if (normalized !== undefined) spring.set(normalized); }, [normalized, spring]);
  return <div className={cn("space-y-2", className)}>{showLabel && normalized !== undefined && <div className="flex items-center justify-between text-xs"><span className="text-muted-foreground">{label}</span><span className="font-mono font-semibold text-info" dir="ltr">{Math.round(normalized)}%</span></div>}<div role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={normalized} className="relative h-2 overflow-hidden rounded-full bg-foreground/[.07] ring-1 ring-foreground/5"><motion.div className={cn("dip-ai-gradient absolute inset-y-0 start-0 overflow-hidden rounded-full shadow-[0_0_14px_rgb(6_182_212/.7)]", normalized === undefined && "w-2/3 animate-pulse")} style={normalized === undefined ? undefined : { width }}><span aria-hidden="true" className="dip-progress-shimmer absolute inset-y-0 start-0 w-1/3 bg-gradient-to-r from-transparent via-white/40 to-transparent"/></motion.div></div></div>;
}
