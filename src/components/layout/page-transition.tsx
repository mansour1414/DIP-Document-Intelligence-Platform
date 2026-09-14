"use client";
import { usePathname } from "next/navigation";
import { motion, useReducedMotion } from "motion/react";
export function PageTransition({ children }: { children: React.ReactNode }) { const pathname = usePathname(); const reduced = useReducedMotion(); return <motion.div key={pathname} initial={reduced ? false : { y: 16 }} animate={{ y: 0 }} transition={{ duration: reduced ? 0 : .3, ease: [.22,1,.36,1] }}>{children}</motion.div>; }
