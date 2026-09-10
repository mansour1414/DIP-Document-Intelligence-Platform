import { cn } from "@/lib/utils";
export function PageShell({ className, children }: React.HTMLAttributes<HTMLElement>) { return <main className={cn("min-h-screen bg-background text-foreground", className)}>{children}</main>; }
export function Container({ className, children }: React.HTMLAttributes<HTMLDivElement>) { return <div className={cn("dip-container", className)}>{children}</div>; }
