import { privateMetadata } from "@/lib/seo/metadata";
import { redirect } from "next/navigation";
export const metadata = privateMetadata;
export default function SignupPage() { redirect("/en/signup"); }
