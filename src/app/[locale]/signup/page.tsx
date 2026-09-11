import { notFound } from "next/navigation";
import { AuthForm } from "@/components/auth/auth-form";
import { privateMetadata } from "@/lib/seo/metadata";
import { locales, type Locale } from "@/lib/seo/tool-content";
export const metadata = privateMetadata;
export default async function SignupPage({ params }: { params: Promise<{ locale: string }> }) { const { locale } = await params; if (!locales.includes(locale as Locale)) notFound(); return <AuthForm mode="signup" locale={locale as Locale} githubEnabled={Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET)}/>; }
