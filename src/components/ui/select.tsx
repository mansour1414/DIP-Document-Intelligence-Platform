import * as React from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";
export const Select = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(({ className, children, ...props }, ref) => <span className="relative block"><select ref={ref} className={cn("min-h-11 w-full appearance-none rounded-lg border border-input bg-card py-2 ps-3 pe-10 text-sm text-card-foreground shadow-sm transition-[border-color,box-shadow] focus-visible:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/25 disabled:cursor-not-allowed disabled:bg-muted disabled:opacity-70", className)} {...props}>{children}</select><ChevronDown aria-hidden="true" className="pointer-events-none absolute end-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /></span>);
Select.displayName = "Select";
