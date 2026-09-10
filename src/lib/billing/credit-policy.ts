import type { CreditReason } from "@prisma/client";
import { MONETIZATION_POLICY_VERSION } from "@/lib/entitlements/policy";
export const CREDIT_POLICY={version:MONETIZATION_POLICY_VERSION,toolCosts:{"word-to-pdf":1,"pdf-to-word":1,"excel-to-pdf":1,"powerpoint-to-pdf":1,"ocr-pdf":3,"summarize-pdf":5,"chat-with-pdf":5,"extract-data":5} as Readonly<Record<string,number>>,defaultServerToolCost:1} as const;
export function creditCost(toolId:string){return CREDIT_POLICY.toolCosts[toolId]??CREDIT_POLICY.defaultServerToolCost}
export function creditReason(toolId:string):CreditReason{return ["summarize-pdf","chat-with-pdf","extract-data"].includes(toolId)?"AI_USAGE":"TOOL_EXECUTION"}
