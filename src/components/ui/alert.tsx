import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";
const alertVariants = cva("rounded-xl border px-4 py-3 text-sm leading-6", { variants: { variant: { info: "border-info/20 bg-info-surface text-info", success: "border-success/20 bg-success-surface text-success", warning: "border-warning/20 bg-warning-surface text-warning", destructive: "border-destructive/20 bg-destructive/10 text-destructive" } }, defaultVariants: { variant: "info" } });
export function Alert({ className, variant, ...props }: React.HTMLAttributes<HTMLDivElement> & VariantProps<typeof alertVariants>) { return <div className={cn(alertVariants({ variant }), className)} {...props} />; }
