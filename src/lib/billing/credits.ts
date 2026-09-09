import { db } from "@/lib/db";

export const toolCredits: Record<string, number> = {
  "word-to-pdf": 1, "pdf-to-word": 1, "excel-to-pdf": 1, "powerpoint-to-pdf": 1,
  "ocr-pdf": 3, "summarize-pdf": 5, "chat-with-pdf": 5, "extract-data": 5,
};

export const plans = {
  FREE: { name: "Free", monthlyCredits: 20 },
  PRO: { name: "Pro", monthlyCredits: 500 },
  BUSINESS: { name: "Enterprise", monthlyCredits: 2_000 },
} as const;

export class CreditError extends Error { constructor(message: string) { super(message); } }

export async function creditBalance(userId: string) {
  const latest = await db.creditLedger.findFirst({ where: { userId }, orderBy: { createdAt: "desc" }, select: { balance: true } });
  return Number(latest?.balance ?? 0);
}

export async function consumeCredits(userId: string, toolId: string, reference: string) {
  const cost = toolCredits[toolId] ?? 1;
  return db.$transaction(async (tx) => {
    const latest = await tx.creditLedger.findFirst({ where: { userId }, orderBy: { createdAt: "desc" }, select: { balance: true } });
    const balance = Number(latest?.balance ?? 0);
    if (balance < cost) throw new CreditError("INSUFFICIENT_CREDITS");
    return tx.creditLedger.create({ data: { userId, type: "USAGE", amount: -cost, balance: balance - cost, reference }, select: { balance: true } });
  }, { isolationLevel: "Serializable" });
}

export async function grantSignupCredits(userId: string) {
  return db.creditLedger.create({ data: { userId, type: "BONUS", amount: plans.FREE.monthlyCredits, balance: plans.FREE.monthlyCredits, reference: "signup-bonus" } });
}
