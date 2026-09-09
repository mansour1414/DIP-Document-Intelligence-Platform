"use client";

import Link from "next/link";
import { toolsConfig } from "@/config";
import { LanguageToggle, useLocale } from "@/components/i18n/locale-provider";

export default function Home() {
  const { locale } = useLocale();
  const ar = locale === "ar";
  return (
    <div className="flex flex-col min-h-screen">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 font-bold text-xl">
            <span className="bg-blue-600 text-white px-2 py-1 rounded-lg text-sm">
              DIP
            </span>
            <span className="hidden sm:inline">Document Intelligence</span>
          </Link>
          <nav className="flex items-center gap-6">
            <LanguageToggle />
            <Link
              href="#tools"
              className="text-sm text-gray-600 hover:text-gray-900"
            >
              {ar ? "الأدوات" : "Tools"}
            </Link>
            <Link
              href="#pricing"
              className="text-sm text-gray-600 hover:text-gray-900"
            >
              {ar ? "الأسعار" : "Pricing"}
            </Link>
            <Link
              href="/login"
              className="text-sm text-gray-600 hover:text-gray-900"
            >
              {ar ? "تسجيل الدخول" : "Login"}
            </Link>
            <Link
              href="/signup"
              className="text-sm bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            >
              {ar ? "ابدأ الآن" : "Get Started"}
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <section className="py-20 px-4">
        <div className="container mx-auto text-center max-w-3xl">
          <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-6">
            {ar ? "منصة ذكاء" : "Document Intelligence"}
            <span className="text-blue-600 block">{ar ? "المستندات" : "Platform"}</span>
          </h1>
          <p className="text-lg text-gray-600 mb-8 max-w-xl mx-auto">
            {ar ? "عالج مستنداتك وحوّلها وافهمها بأدوات مدعومة بالذكاء الاصطناعي. خصوصيتك أولاً، بسرعة، وبدعم كامل للعربية والإنجليزية." : "Process, convert, and understand your documents with AI-powered tools. Privacy-first, fast, and supports Arabic & English."}
          </p>
          <div className="flex gap-4 justify-center">
            <Link
              href="#tools"
              className="bg-blue-600 text-white px-8 py-3 rounded-lg font-medium hover:bg-blue-700 transition-colors"
            >
              {ar ? "ابدأ مجاناً" : "Start for Free"}
            </Link>
            <Link
              href="#features"
              className="border border-gray-300 px-8 py-3 rounded-lg font-medium hover:bg-gray-50 transition-colors"
            >
              {ar ? "اعرف المزيد" : "Learn More"}
            </Link>
          </div>
        </div>
      </section>

      {/* Privacy Banner */}
      <section className="bg-green-50 border-y">
        <div className="container mx-auto px-4 py-6 text-center">
          <p className="text-green-800 font-medium">
            {ar ? "ملفاتك تبقى خاصة — تعمل معظم الأدوات مباشرة في المتصفح، ولا تغادر ملفاتك جهازك." : "🔒 Your files stay private — Most tools work directly in your browser. Your files never leave your device."}
          </p>
        </div>
      </section>

      {/* Tools Grid */}
      <section id="tools" className="py-20 px-4">
        <div className="container mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">{ar ? "أدوات المستندات" : "PDF Tools"}</h2>
            <p className="text-gray-600">
              {ar ? "كل ما تحتاجه لمعالجة وتحويل ملفاتك" : "Everything you need to work with PDF files"}
            </p>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-5xl mx-auto">
            {toolsConfig.map((tool) => (
              <Link
                key={tool.id}
                href={tool.href}
                className="group p-6 rounded-xl border bg-white hover:shadow-lg hover:border-blue-200 transition-all text-center"
              >
                <div className="text-3xl mb-3">
                  {tool.category === "ai"
                    ? "✨"
                    : tool.category === "convert"
                      ? "🔄"
                      : tool.category === "edit"
                        ? "✏️"
                        : "📄"}
                </div>
                <h3 className="font-semibold text-sm group-hover:text-blue-600 transition-colors">
                  {ar ? tool.nameAr : tool.name}
                </h3>
                <p className="text-xs text-gray-500 mt-1">{ar ? tool.descriptionAr : tool.description}</p>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-20 px-4 bg-gray-50">
        <div className="container mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">{ar ? "لماذا DIP؟" : "Why DIP?"}</h2>
          </div>
          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="text-center p-6">
              <div className="text-4xl mb-4">🤖</div>
              <h3 className="font-semibold mb-2">{ar ? "مدعومة بالذكاء الاصطناعي" : "AI-Powered"}</h3>
              <p className="text-sm text-gray-600">
                {ar ? "لخّص مستنداتك، وتحدث معها، واستخرج بياناتها باستخدام الذكاء الاصطناعي المتقدم." : "Summarize, chat with, and extract data from your documents using advanced AI."}
              </p>
            </div>
            <div className="text-center p-6">
              <div className="text-4xl mb-4">🔒</div>
              <h3 className="font-semibold mb-2">{ar ? "الخصوصية أولاً" : "Privacy First"}</h3>
              <p className="text-sm text-gray-600">
                {ar ? "تتم معظم المعالجة داخل متصفحك. لا تغادر ملفاتك جهازك." : "Most processing happens in your browser. Your files never leave your device."}
              </p>
            </div>
            <div className="text-center p-6">
              <div className="text-4xl mb-4">🌍</div>
              <h3 className="font-semibold mb-2">{ar ? "العربية والإنجليزية" : "Arabic & English"}</h3>
              <p className="text-sm text-gray-600">
                {ar ? "دعم كامل للعربية والإنجليزية مع اتجاه RTL وأدوات مترجمة." : "Full support for Arabic and English with RTL layout and localized tools."}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t py-8 px-4 mt-auto">
        <div className="container mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 font-bold">
            <span className="bg-blue-600 text-white px-2 py-1 rounded-lg text-xs">
              DIP
            </span>
            <span className="text-sm text-gray-500">
              {ar ? "© 2026 جميع الحقوق محفوظة." : "© 2026 All rights reserved."}
            </span>
          </div>
          <div className="flex gap-6 text-sm text-gray-500">
            <Link href="/privacy" className="hover:text-gray-900">
              {ar ? "الخصوصية" : "Privacy"}
            </Link>
            <Link href="/terms" className="hover:text-gray-900">
              {ar ? "الشروط" : "Terms"}
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
