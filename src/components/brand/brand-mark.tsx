import Image from "next/image";
import Link from "next/link";
import { cn } from "@/lib/utils";

export function BrandMark({ href = "/", className }: { href?: string; className?: string }) {
  return <Link href={href} aria-label="DIP home" className={cn("group inline-flex min-h-11 items-center rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background", className)}><Image src="/brand/dip-logo.svg" width={106} height={56} priority alt="DIP" className="h-11 w-auto drop-shadow-[0_0_12px_rgb(6_182_212/.16)] transition-[filter,transform] duration-200 group-hover:drop-shadow-[0_0_16px_rgb(6_182_212/.34)]" /></Link>;
}
