export type AiTool = "summarize-pdf" | "chat-with-pdf" | "extract-data";

export class AiProcessingError extends Error {
  constructor(public readonly code: string, message: string) { super(message); }
}

const MAX_TEXT_LENGTH = 180_000;

function promptFor(tool: AiTool, text: string, locale: "en" | "ar", question?: string) {
  const language = locale === "ar" ? "Arabic" : "English";
  const source = `Document text follows:\n---\n${text}\n---`;
  if (tool === "summarize-pdf") return `You are DIP's document assistant. Summarize this document accurately in ${language}. Use a concise title, key points, and important dates, amounts, or decisions. Do not invent facts. ${source}`;
  if (tool === "extract-data") return `You are DIP's document assistant. Extract the important entities, dates, amounts, contacts, and action items from this document. Respond in ${language} as valid JSON only with keys: summary, entities, dates, amounts, contacts, actionItems. Use empty arrays where data is absent and do not invent facts. ${source}`;
  return `You are DIP's document assistant. Answer the user's question about the document in ${language}. Base the answer only on the document. If the answer is unavailable, say so clearly. Question: ${question ?? ""}\n${source}`;
}

export async function runAiTool(input: { tool: AiTool; text: string; locale: "en" | "ar"; question?: string }) {
  if (!input.text.trim()) throw new AiProcessingError("NO_TEXT", "No readable text was found. Run OCR on scanned documents first.");
  if (input.text.length > MAX_TEXT_LENGTH) input.text = input.text.slice(0, MAX_TEXT_LENGTH);
  if (input.tool === "chat-with-pdf" && !input.question?.trim()) throw new AiProcessingError("MISSING_QUESTION", "Enter a question about the document.");
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new AiProcessingError("AI_NOT_CONFIGURED", "The AI service is not configured. Add GEMINI_API_KEY to the server environment.");
  const model = process.env.GEMINI_MODEL ?? "gemini-2.5-flash";
  const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: promptFor(input.tool, input.text, input.locale, input.question) }] }], generationConfig: { temperature: 0.2 } }),
  });
  const payload = await response.json().catch(() => null) as { candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>; error?: { message?: string } } | null;
  if (!response.ok) throw new AiProcessingError("AI_PROVIDER_ERROR", payload?.error?.message ?? "The AI service could not complete this request.");
  const content = payload?.candidates?.[0]?.content?.parts?.map((part) => part.text ?? "").join("").trim();
  if (!content) throw new AiProcessingError("EMPTY_RESPONSE", "The AI service returned no usable response.");
  return { content, model };
}
