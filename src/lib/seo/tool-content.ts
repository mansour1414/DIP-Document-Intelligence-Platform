import { getTool, toolsConfig, type ExecutionMode } from "@/config";

export const locales = ["en", "ar"] as const;
export type Locale = (typeof locales)[number];

export const mvpToolIds = [
  "merge-pdf", "split-pdf", "compress-pdf", "organize-pdf", "rotate-pdf", "delete-pages", "extract-pages",
  "jpg-to-pdf", "pdf-to-jpg", "watermark-pdf", "crop-pdf", "page-numbers", "header-footer", "resize-pages", "alternate-mix", "flip-pages", "split-pdf-by-size", "split-pdf-by-bookmarks", "split-pdf-by-text", "n-up-pdf", "remove-annotations", "word-to-pdf", "pdf-to-word", "excel-to-pdf", "powerpoint-to-pdf", "ocr-pdf",
  "summarize-pdf", "chat-with-pdf", "extract-data",
] as const;
export type MvpToolId = (typeof mvpToolIds)[number];

type FAQ = { question: string; answer: string };
export type ToolSeoContent = {
  toolId: MvpToolId; slug: string; locale: Locale; title: string; description: string; h1: string; intro: string;
  steps: string[]; benefits: string[]; faq: FAQ[]; relatedTools: MvpToolId[]; privacyNote: string;
  status: "stable" | "beta"; indexability: "index";
};

const related: Record<MvpToolId, MvpToolId[]> = {
  "merge-pdf": ["split-pdf", "compress-pdf"], "split-pdf": ["merge-pdf", "extract-pages"],
  "compress-pdf": ["merge-pdf", "pdf-to-jpg"], "organize-pdf": ["rotate-pdf", "delete-pages"],
  "rotate-pdf": ["organize-pdf", "delete-pages"], "delete-pages": ["organize-pdf", "extract-pages"],
  "extract-pages": ["split-pdf", "delete-pages"], "jpg-to-pdf": ["pdf-to-jpg", "merge-pdf"],
  "pdf-to-jpg": ["jpg-to-pdf", "compress-pdf"], "watermark-pdf": ["organize-pdf", "compress-pdf"],
  "crop-pdf": ["organize-pdf", "page-numbers"], "page-numbers": ["header-footer", "crop-pdf"], "header-footer": ["page-numbers", "watermark-pdf"],
  "resize-pages": ["crop-pdf", "flip-pages"], "alternate-mix": ["merge-pdf", "organize-pdf"], "flip-pages": ["rotate-pdf", "resize-pages"],
  "split-pdf-by-size": ["split-pdf", "compress-pdf"], "split-pdf-by-bookmarks": ["split-pdf", "extract-pages"], "split-pdf-by-text": ["split-pdf", "ocr-pdf"],
  "n-up-pdf": ["resize-pages", "page-numbers"], "remove-annotations": ["organize-pdf", "watermark-pdf"],
  "word-to-pdf": ["pdf-to-word", "excel-to-pdf"], "pdf-to-word": ["word-to-pdf", "ocr-pdf"],
  "excel-to-pdf": ["word-to-pdf", "powerpoint-to-pdf"], "powerpoint-to-pdf": ["word-to-pdf", "excel-to-pdf"],
  "ocr-pdf": ["extract-data", "summarize-pdf"], "summarize-pdf": ["chat-with-pdf", "ocr-pdf"],
  "chat-with-pdf": ["summarize-pdf", "extract-data"], "extract-data": ["ocr-pdf", "summarize-pdf"],
};

const enDetails: Record<MvpToolId, { intent: string; result: string; use: string; caveat: string }> = {
  "merge-pdf": { intent: "combine several PDFs in the order you choose", result: "one consolidated PDF", use: "reports, application packs, and scanned batches", caveat: "The output follows the file order you set." },
  "split-pdf": { intent: "separate a PDF into smaller documents", result: "individual PDF parts", use: "sharing chapters or archiving sections", caveat: "Choose page ranges carefully before processing." },
  "compress-pdf": { intent: "reduce a PDF file size for easier sharing", result: "a smaller PDF", use: "email attachments and upload limits", caveat: "Compression may reduce image detail depending on the selected quality." },
  "organize-pdf": { intent: "reorder pages into the sequence you need", result: "a reorganized PDF", use: "fixing scan order and assembling packets", caveat: "Review the page sequence before downloading." },
  "rotate-pdf": { intent: "correct the orientation of PDF pages", result: "a PDF with rotated pages", use: "sideways scans and mixed-orientation files", caveat: "Rotation changes page orientation, not the underlying text." },
  "delete-pages": { intent: "remove unwanted pages from a PDF", result: "a cleaned PDF", use: "removing blanks, covers, or irrelevant appendices", caveat: "Keep at least one page in the output." },
  "extract-pages": { intent: "copy selected pages into a new PDF", result: "a focused PDF containing only chosen pages", use: "sharing excerpts without the full document", caveat: "Page numbers refer to the original file order." },
  "jpg-to-pdf": { intent: "turn JPG or PNG images into a PDF", result: "one image-based PDF", use: "receipts, photos, and scanned paperwork", caveat: "Source resolution determines visible image quality." },
  "pdf-to-jpg": { intent: "render PDF pages as JPG images", result: "downloadable page images", use: "previews, slides, and image workflows", caveat: "Rendered images do not retain selectable PDF text." },
  "watermark-pdf": { intent: "apply a text watermark to PDF pages", result: "a marked PDF", use: "draft, confidential, or ownership labels", caveat: "Preview wording and placement before distribution." },
  "crop-pdf": { intent: "adjust the visible area of PDF pages", result: "a PDF with updated CropBox boundaries", use: "trimming margins and focusing the visible page area", caveat: "Cropping does not delete hidden content and must not be used as redaction." },
  "page-numbers": { intent: "add page numbers in a chosen position", result: "a numbered PDF", use: "reports, submissions, and printed document sets", caveat: "Review mixed-size and rotated pages before distribution." },
  "header-footer": { intent: "add Arabic or English header and footer text", result: "a PDF with consistent page labels", use: "document titles, classifications, and reference labels", caveat: "Keep text concise so it fits safely within page margins." },
  "resize-pages": { intent: "resize pages to A3, A4, Letter, or Legal dimensions", result: "a PDF with consistent page dimensions", use: "standardizing mixed scans and preparing documents for printing", caveat: "Contain preserves proportions with possible whitespace; Stretch fills the page and may distort content." },
  "alternate-mix": { intent: "interleave pages from exactly two PDF files", result: "one PDF with alternating pages", use: "combining separately scanned odd and even pages", caveat: "Check file order and reverse the second file when its scan order runs backwards." },
  "flip-pages": { intent: "mirror all or selected PDF pages horizontally or vertically", result: "a PDF with the chosen pages flipped", use: "correcting mirrored scans and reversed page images", caveat: "Flipping changes the page appearance and is different from rotating the page." },
  "split-pdf-by-size": { intent: "split a PDF into deterministic parts near a requested byte target", result: "multiple reopenable PDF parts", use: "upload limits and bounded document delivery", caveat: "The target is approximate, and a single page may exceed it because PDF serialization is not exactly size-predictable." },
  "split-pdf-by-bookmarks": { intent: "split a PDF at safe direct internal bookmark destinations", result: "chapter-like PDF parts", use: "structured manuals and bookmarked reports", caveat: "External, remote, named, malformed, or invalid destinations are rejected instead of guessed." },
  "split-pdf-by-text": { intent: "start a new part before each page containing literal text", result: "text-delimited PDF parts", use: "repeated section headings in searchable PDFs", caveat: "Matching is literal and deterministic; image-only pages are not OCRed automatically." },
  "n-up-pdf": { intent: "compose 2, 4, 6, or 9 source pages on each output sheet", result: "a compact imposed PDF", use: "handouts and print review", caveat: "Interactive links, forms, and annotations are not preserved as interactive objects." },
  "remove-annotations": { intent: "selectively remove comment annotations while preserving form widgets", result: "a PDF with the chosen comments removed", use: "clean review copies", caveat: "Signed PDFs are rejected because rewriting may invalidate signature integrity; links are removed only when explicitly selected." },
  "word-to-pdf": { intent: "convert Word documents to a consistent PDF", result: "a shareable PDF", use: "contracts, reports, and final copies", caveat: "Complex fonts or layouts can render differently from Word." },
  "pdf-to-word": { intent: "convert PDF content into an editable Word document", result: "a DOCX file", use: "reusing text from straightforward PDFs", caveat: "This beta works best on simple layouts; complex formatting may need correction." },
  "excel-to-pdf": { intent: "convert Excel spreadsheets into shareable PDF documents", result: "a PDF rendered from the workbook", use: "reports, tables, and spreadsheet distribution", caveat: "Wide sheets, print areas, charts, fonts, and page breaks may render differently and should be reviewed." },
  "powerpoint-to-pdf": { intent: "convert PowerPoint presentations into PDF documents", result: "a PDF rendered from the slides", use: "sharing decks, handouts, and stable presentation copies", caveat: "Transitions, animations, media, custom fonts, and complex layouts may not be preserved exactly." },
  "ocr-pdf": { intent: "add searchable text to scanned documents in Arabic and English", result: "a searchable PDF", use: "scans, photographed pages, and archives", caveat: "Accuracy depends on scan quality, resolution, language, and source layout." },
  "summarize-pdf": { intent: "create an AI-assisted summary of a PDF", result: "a concise document overview", use: "long reports, policies, and research reading", caveat: "Review important facts against the source and its page references." },
  "chat-with-pdf": { intent: "ask focused questions about one PDF", result: "AI-generated answers grounded in the document", use: "finding clauses, facts, and explanations", caveat: "Answers can be incomplete; verify them against cited source pages when available." },
  "extract-data": { intent: "identify structured facts with AI", result: "organized entities, dates, amounts, contacts, and actions", use: "reviewing forms, invoices, and business documents", caveat: "Validate extracted fields before using them in decisions or systems." },
};

const arDetails: Record<MvpToolId, { intent: string; result: string; use: string; caveat: string }> = {
  "merge-pdf": { intent: "جمع عدة ملفات PDF بالترتيب الذي تختاره", result: "ملف PDF موحّد", use: "التقارير وملفات التقديم ودفعات المسح", caveat: "يتبع الناتج ترتيب الملفات الذي تحدده." },
  "split-pdf": { intent: "تقسيم ملف PDF إلى مستندات أصغر", result: "أجزاء PDF مستقلة", use: "مشاركة الفصول أو أرشفة الأقسام", caveat: "راجع نطاقات الصفحات قبل المعالجة." },
  "compress-pdf": { intent: "تقليل حجم PDF لتسهيل مشاركته", result: "ملف PDF أصغر", use: "مرفقات البريد وحدود الرفع", caveat: "قد يقل وضوح الصور بحسب مستوى الجودة المختار." },
  "organize-pdf": { intent: "إعادة ترتيب الصفحات بالتسلسل المطلوب", result: "ملف PDF مرتب", use: "تصحيح ترتيب المسح وتجميع الملفات", caveat: "راجع تسلسل الصفحات قبل التنزيل." },
  "rotate-pdf": { intent: "تصحيح اتجاه صفحات PDF", result: "ملف بصفحات مدوّرة", use: "الصور الممسوحة الجانبية والملفات مختلفة الاتجاه", caveat: "التدوير يغيّر اتجاه الصفحة ولا يغيّر النص الأصلي." },
  "delete-pages": { intent: "إزالة الصفحات غير المطلوبة", result: "ملف PDF منقّح", use: "حذف الصفحات الفارغة أو الأغلفة أو الملاحق", caveat: "يجب إبقاء صفحة واحدة على الأقل." },
  "extract-pages": { intent: "نسخ صفحات محددة إلى ملف جديد", result: "ملف PDF يضم الصفحات المختارة فقط", use: "مشاركة مقتطف دون كامل المستند", caveat: "أرقام الصفحات تتبع ترتيب الملف الأصلي." },
  "jpg-to-pdf": { intent: "تحويل صور JPG أو PNG إلى PDF", result: "ملف PDF واحد من الصور", use: "الإيصالات والصور والمستندات الممسوحة", caveat: "دقة المصدر تحدد وضوح الصور في الناتج." },
  "pdf-to-jpg": { intent: "تحويل صفحات PDF إلى صور JPG", result: "صور قابلة للتنزيل لكل صفحة", use: "المعاينات والعروض وسير عمل الصور", caveat: "الصور الناتجة لا تحتفظ بالنص القابل للتحديد." },
  "watermark-pdf": { intent: "إضافة علامة مائية نصية إلى الصفحات", result: "ملف PDF موسوم", use: "تمييز المسودات والمحتوى السري والملكية", caveat: "راجع النص وموضعه قبل توزيع الملف." },
  "crop-pdf": { intent: "ضبط المساحة الظاهرة من صفحات PDF", result: "ملف PDF بحدود CropBox محدثة", use: "تقليل الهوامش والتركيز على المساحة الظاهرة", caveat: "لا يحذف القص المحتوى المخفي ولا يجوز استخدامه كإخفاء آمن للبيانات." },
  "page-numbers": { intent: "إضافة أرقام الصفحات في الموضع المختار", result: "ملف PDF مرقم", use: "التقارير وملفات التقديم والمستندات المطبوعة", caveat: "راجع الصفحات مختلفة الأحجام والمدوّرة قبل توزيع الملف." },
  "header-footer": { intent: "إضافة نص عربي أو إنجليزي في الرأس والتذييل", result: "ملف PDF بعناوين صفحات متسقة", use: "عناوين المستندات والتصنيفات والمراجع", caveat: "استخدم نصًا موجزًا ليتسع بأمان داخل هوامش الصفحة." },
  "resize-pages": { intent: "تغيير الصفحات إلى أبعاد A3 أو A4 أو Letter أو Legal", result: "ملف PDF بأبعاد صفحات متسقة", use: "توحيد الملفات الممسوحة مختلفة الأحجام وتجهيز المستندات للطباعة", caveat: "يحافظ خيار الاحتواء على النسب وقد يضيف فراغًا، بينما قد يؤدي التمديد إلى تشويه المحتوى." },
  "alternate-mix": { intent: "دمج صفحات ملفي PDF بالتناوب", result: "ملف PDF واحد بصفحات متناوبة", use: "جمع الصفحات الفردية والزوجية الممسوحة في ملفين منفصلين", caveat: "راجع ترتيب الملفين واعكس الملف الثاني عندما يكون ترتيب المسح فيه تنازليًا." },
  "flip-pages": { intent: "عكس كل صفحات PDF أو صفحات محددة أفقيًا أو رأسيًا", result: "ملف PDF بصفحات معكوسة وفق الاختيار", use: "تصحيح المسوح المعكوسة وصور الصفحات المقلوبة مرآتيًا", caveat: "القلب يغيّر مظهر الصفحة ويختلف عن تدويرها." },
  "split-pdf-by-size": { intent: "تقسيم PDF إلى أجزاء حتمية قريبة من حجم بايتات مستهدف", result: "عدة أجزاء PDF قابلة لإعادة الفتح", use: "حدود الرفع وتسليم المستندات ضمن حجم مقيد", caveat: "الحجم تقريبي وقد تتجاوز صفحة واحدة الهدف لأن تسلسل PDF لا يسمح بضمان حجم دقيق." },
  "split-pdf-by-bookmarks": { intent: "تقسيم PDF عند وجهات الإشارات المرجعية الداخلية المباشرة والآمنة", result: "أجزاء PDF شبيهة بالفصول", use: "الأدلة والتقارير ذات الإشارات المرجعية", caveat: "تُرفض الوجهات الخارجية والبعيدة والمسمّاة والمشوهة أو غير الصالحة بدل التخمين." },
  "split-pdf-by-text": { intent: "بدء جزء جديد قبل كل صفحة تحتوي نصًا حرفيًا", result: "أجزاء PDF تفصلها مطابقة النص", use: "العناوين المتكررة في ملفات PDF القابلة للبحث", caveat: "المطابقة حرفية وحتمية ولا يُشغّل OCR تلقائيًا للصفحات المصورة." },
  "n-up-pdf": { intent: "تجميع صفحتين أو 4 أو 6 أو 9 صفحات مصدر في كل ورقة ناتجة", result: "ملف PDF مدمج للعرض أو الطباعة", use: "النشرات والمراجعة المطبوعة", caveat: "لا تُحفظ الروابط والنماذج والتعليقات كعناصر تفاعلية." },
  "remove-annotations": { intent: "إزالة تعليقات توضيحية منتقاة مع الحفاظ على عناصر النماذج", result: "ملف PDF أزيلت منه التعليقات المختارة", use: "إنشاء نسخ مراجعة نظيفة", caveat: "تُرفض الملفات الموقعة لأن إعادة الكتابة قد تبطل التوقيع، ولا تزال الروابط إلا باختيار صريح." },
  "word-to-pdf": { intent: "تحويل مستند Word إلى PDF ثابت", result: "ملف PDF سهل المشاركة", use: "العقود والتقارير والنسخ النهائية", caveat: "قد تختلف الخطوط أو التخطيطات المعقدة عن Word." },
  "pdf-to-word": { intent: "تحويل محتوى PDF إلى مستند Word قابل للتحرير", result: "ملف DOCX", use: "إعادة استخدام نصوص الملفات البسيطة", caveat: "هذه نسخة تجريبية تناسب التخطيطات البسيطة؛ وقد تحتاج التنسيقات المعقدة إلى تصحيح." },
  "excel-to-pdf": { intent: "تحويل جداول Excel إلى مستندات PDF قابلة للمشاركة", result: "ملف PDF منشأ من المصنف", use: "التقارير والجداول وتوزيع بيانات جداول البيانات", caveat: "قد تختلف الأوراق العريضة ومناطق الطباعة والمخططات والخطوط وفواصل الصفحات، لذا راجع الناتج." },
  "powerpoint-to-pdf": { intent: "تحويل عروض PowerPoint إلى مستندات PDF", result: "ملف PDF منشأ من الشرائح", use: "مشاركة العروض والنشرات والنسخ الثابتة", caveat: "قد لا تُحفظ الانتقالات والحركات والوسائط والخطوط المخصصة والتخطيطات المعقدة كما هي تمامًا." },
  "ocr-pdf": { intent: "إضافة نص قابل للبحث للمستندات الممسوحة بالعربية والإنجليزية", result: "ملف PDF قابل للبحث", use: "المسوح والصور والأرشيف", caveat: "تعتمد الدقة على جودة المسح والدقة واللغة وتخطيط المصدر." },
  "summarize-pdf": { intent: "إنشاء ملخص بمساعدة الذكاء الاصطناعي", result: "نظرة موجزة على المستند", use: "التقارير الطويلة والسياسات والبحوث", caveat: "راجع المعلومات المهمة مع المصدر وإشارات الصفحات." },
  "chat-with-pdf": { intent: "طرح أسئلة محددة حول ملف PDF واحد", result: "إجابات مولّدة بالذكاء الاصطناعي ومستندة إلى الملف", use: "العثور على البنود والحقائق والتفسيرات", caveat: "قد تكون الإجابات ناقصة؛ تحقق منها عبر صفحات المصدر المشار إليها عند توفرها." },
  "extract-data": { intent: "استخراج حقائق منظمة بالذكاء الاصطناعي", result: "كيانات وتواريخ ومبالغ وجهات اتصال وإجراءات منظمة", use: "مراجعة النماذج والفواتير ومستندات الأعمال", caveat: "تحقق من الحقول المستخرجة قبل استخدامها في قرار أو نظام." },
};

function privacy(mode: ExecutionMode, locale: Locale) {
  if (locale === "ar") return mode === "client" ? "تتم المعالجة داخل متصفحك لهذه الأداة، ولا يُرفع محتوى الملف إلى عامل المعالجة." : mode === "ai" ? "يُعالج المستند عبر عامل DIP، وقد يُرسل النص اللازم فقط إلى مزود الذكاء الاصطناعي وفق سياسة المزود. لا ترسل مستندات لا تملك صلاحية معالجتها." : "يُرفع الملف إلى مساحة معالجة خادمية مؤقتة ومعزولة لإنشاء النتيجة، ثم تطبق عليه سياسة الاحتفاظ والحذف الخاصة بالخدمة.";
  return mode === "client" ? "This tool processes the document in your browser; its file content is not uploaded to the processing worker." : mode === "ai" ? "The document is processed by a DIP worker, and only required text may be sent to the AI provider under its policy. Do not submit documents you are not authorized to process." : "The file is uploaded to a temporary isolated server workspace to create the result, subject to the service retention and deletion policy.";
}

function build(toolId: MvpToolId, locale: Locale): ToolSeoContent {
  const tool = getTool(toolId)!; const d = locale === "ar" ? arDetails[toolId] : enDetails[toolId]; const name = locale === "ar" ? tool.nameAr : tool.name;
  const beta = toolId === "pdf-to-word";
  const officeWorker = ["excel-to-pdf", "powerpoint-to-pdf"].includes(toolId);
  const processingNote = officeWorker ? (locale === "ar" ? "يُرفع الملف إلى عامل LibreOffice خادمي داخل مساحة معالجة مؤقتة ومعزولة لإنشاء ملف PDF. راجع الناتج لأن التخطيطات والخطوط والوسائط المعقدة قد تختلف." : "The file is uploaded to a server-side LibreOffice worker in a temporary isolated workspace to create the PDF. Review the result because complex layouts, fonts, and media can differ.") : privacy(tool.execution, locale);
  return {
    toolId, slug: toolId, locale,
    title: locale === "ar" ? `${name} أونلاين${beta ? " — تجريبي" : ""} | DIP` : `${name} Online${beta ? " — Beta" : ""} | DIP`,
    description: locale === "ar" ? `${name} يساعدك على ${d.intent} بخطوات واضحة ودعم كامل للواجهة العربية.` : `Use ${name} to ${d.intent} with clear steps, practical limits, and privacy-aware processing.`,
    h1: locale === "ar" ? `${name} أونلاين` : `${name} Online`,
    intro: locale === "ar" ? `استخدم ${name} من DIP من أجل ${d.intent}. يناسب ${d.use}، ويمنحك ${d.result} دون إعدادات معقدة.` : `Use DIP to ${d.intent}. It is useful for ${d.use} and produces ${d.result} without a complicated setup.`,
    steps: locale === "ar" ? ["اختر الملف أو الملفات المطلوبة.", "اضبط الخيارات والترتيب المتاحين لهذه الأداة.", "ابدأ المعالجة وانتظر اكتمال النتيجة.", "راجع الناتج ثم نزّله إلى جهازك."] : ["Choose the document or files you need.", "Set the options or order available for this tool.", "Start processing and wait for the result.", "Review the output, then download it to your device."],
    benefits: locale === "ar" ? [`ناتج واضح: ${d.result}.`, `مناسب لـ${d.use}.`, d.caveat] : [`A clear output: ${d.result}.`, `Designed for ${d.use}.`, d.caveat],
    faq: locale === "ar" ? [
      { question: `ماذا تفعل أداة ${name}؟`, answer: `تساعدك على ${d.intent}، وتنتج ${d.result}.` },
      { question: "أين تتم معالجة الملف؟", answer: processingNote },
      { question: "ما الذي يؤثر في النتيجة؟", answer: d.caveat },
      ...(toolId === "ocr-pdf" ? [{ question: "هل يدعم OCR العربية؟", answer: "نعم، يدعم التعرّف على العربية والإنجليزية. تعتمد الدقة على جودة المسح والدقة وتخطيط الصفحة، ولا يمكن ضمان دقة كاملة." }] : []),
      ...(beta ? [{ question: "هل التحويل إلى Word نهائي؟", answer: "الأداة في مرحلة تجريبية. راجع الجداول والخطوط والتخطيطات المعقدة بعد التحويل." }] : []),
    ] : [
      { question: `What does ${name} do?`, answer: `It lets you ${d.intent} and produces ${d.result}.` },
      { question: "Where is my file processed?", answer: processingNote },
      { question: "What affects the result?", answer: d.caveat },
      ...(toolId === "ocr-pdf" ? [{ question: "Does OCR support Arabic?", answer: "Yes. Recognition supports Arabic and English. Accuracy depends on scan quality, resolution, and layout; perfect accuracy is not guaranteed." }] : []),
      ...(beta ? [{ question: "Is PDF to Word production-ready?", answer: "It is a beta. Review tables, fonts, and complex layouts after conversion." }] : []),
    ],
    relatedTools: related[toolId], privacyNote: processingNote, status: beta ? "beta" : "stable", indexability: "index",
  };
}

export const toolSeoContent = Object.fromEntries(mvpToolIds.flatMap((id) => locales.map((locale) => [`${locale}:${id}`, build(id, locale)]))) as Record<`${Locale}:${MvpToolId}`, ToolSeoContent>;
export const getToolSeo = (toolId: string, locale: Locale) => toolSeoContent[`${locale}:${toolId as MvpToolId}`];
export const isMvpTool = (id: string): id is MvpToolId => (mvpToolIds as readonly string[]).includes(id);
export const nonMvpTools = toolsConfig.filter((tool) => !isMvpTool(tool.id));
