import { AuthForm } from "@/components/auth/auth-form";
import { privateMetadata } from "@/lib/seo/metadata";
export const metadata = privateMetadata;
export default function LoginPage() { return <AuthForm mode="signin" />; }
