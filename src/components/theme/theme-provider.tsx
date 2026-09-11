"use client";
import { createContext, useContext, useEffect, useState } from "react";
export type Theme = "light" | "dark" | "system";
const ThemeContext = createContext<{ theme: Theme; setTheme: (theme: Theme) => void }>({ theme: "system", setTheme: () => undefined });
function apply(theme: Theme) { const dark = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches); document.documentElement.classList.toggle("dark", dark); document.documentElement.dataset.theme = theme; }
export function ThemeProvider({ children }: { children: React.ReactNode }) { const [theme, update] = useState<Theme>("system"); useEffect(() => { const stored = localStorage.getItem("dip-theme"); const initial = stored === "light" || stored === "dark" ? stored : "system"; apply(initial); queueMicrotask(() => update(initial)); const media = window.matchMedia("(prefers-color-scheme: dark)"); const listener = () => { if ((localStorage.getItem("dip-theme") ?? "system") === "system") apply("system"); }; media.addEventListener("change", listener); return () => media.removeEventListener("change", listener); }, []); const setTheme = (next: Theme) => { localStorage.setItem("dip-theme", next); update(next); apply(next); }; return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>; }
export const useTheme = () => useContext(ThemeContext);
