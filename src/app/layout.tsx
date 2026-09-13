import type { Metadata } from "next";
import { Inter } from "next/font/google";
import Script from "next/script";
import { LocaleProvider } from "@/components/i18n/locale-provider";
import { ThemeProvider } from "@/components/theme/theme-provider";
import { PageTransition } from "@/components/layout/page-transition";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000"),
  title: "DIP — Document Intelligence Platform",
  description:
    "Global document processing platform combining PDF tools with AI, OCR, and workflow — with privacy-first approach and full Arabic/English support.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning className={`${inter.variable} h-full`}>
      <head><Script id="dip-theme-init" strategy="beforeInteractive" dangerouslySetInnerHTML={{ __html: `(function(){try{var t=localStorage.getItem('dip-theme')||'system';var d=t==='dark'||(t==='system'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d);document.documentElement.dataset.theme=t}catch(e){}})()` }} /></head>
      <body className="min-h-full flex flex-col font-sans antialiased">
        <ThemeProvider><LocaleProvider><PageTransition>{children}</PageTransition></LocaleProvider></ThemeProvider>
      </body>
    </html>
  );
}
