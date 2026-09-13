import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-xl text-sm font-semibold transition-[background-color,border-color,color,box-shadow,transform] duration-200 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/80 focus-visible:ring-offset-2 focus-visible:ring-offset-background active:scale-[.97] disabled:pointer-events-none disabled:scale-100 disabled:opacity-50 disabled:shadow-none [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default: "border border-white/10 bg-primary text-primary-foreground shadow-[inset_0_1px_0_rgb(255_255_255/.16),0_12px_26px_-14px_rgb(79_70_229/.72)] hover:-translate-y-px hover:border-info/50 hover:bg-primary-hover hover:shadow-[0_0_30px_-8px_rgb(6_182_212/.6)]",
        destructive: "bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive-hover",
        outline: "border border-input bg-card/70 text-card-foreground shadow-sm backdrop-blur hover:border-info/45 hover:bg-accent hover:text-accent-foreground",
        secondary: "border border-border bg-secondary/80 text-secondary-foreground backdrop-blur hover:border-info/35 hover:bg-accent",
        ghost: "text-foreground hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-11 px-5",
        sm: "min-h-9 rounded-md px-3",
        lg: "h-13 rounded-xl px-7 text-base",
        icon: "h-10 w-10 p-0",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, type, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        type={Comp === "button" ? type ?? "button" : undefined}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button, buttonVariants };
