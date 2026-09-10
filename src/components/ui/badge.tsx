import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";
const badgeVariants = cva("inline-flex w-fit items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-semibold", { variants: { variant: { default: "border-transparent bg-secondary text-secondary-foreground", outline: "border-border bg-card text-card-foreground", success: "border-success/15 bg-success-surface text-success", warning: "border-warning/15 bg-warning-surface text-warning", info: "border-info/15 bg-info-surface text-info", destructive: "border-destructive/15 bg-destructive/10 text-destructive" } }, defaultVariants: { variant: "default" } });
export function Badge({ className, variant, ...props }: React.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) { return <span className={cn(badgeVariants({ variant }), className)} {...props} />; }
