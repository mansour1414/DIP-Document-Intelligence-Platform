import { Prisma, type CreditReason, type CreditType } from "@prisma/client";
import { withTenant } from "@/lib/db/tenant";
import { PLAN_POLICIES } from "@/lib/entitlements/policy";
import { creditCost, creditReason } from "./credit-policy";
import { randomUUID } from "node:crypto";

export class CreditError extends Error { readonly code="INSUFFICIENT_CREDITS"; constructor(){super("INSUFFICIENT_CREDITS")} }
export async function creditBalance(userId:string){return withTenant({userId},async tx=>{const latest=await tx.creditLedger.findFirst({where:{userId},orderBy:[{createdAt:"desc"},{id:"desc"}],select:{balance:true}});return Number(latest?.balance??0)})}

async function append(input:{userId:string;amount:number;type:CreditType;reason:CreditReason;idempotencyKey:string;reference?:string;metadata?:Prisma.InputJsonValue}){
 return withTenant({userId:input.userId},async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`credit:${input.userId}`},0))`;
  const prior=await tx.creditLedger.findUnique({where:{userId_idempotencyKey:{userId:input.userId,idempotencyKey:input.idempotencyKey}},select:{balance:true}});if(prior)return{balance:prior.balance,reused:true};
  const latest=await tx.creditLedger.findFirst({where:{userId:input.userId},orderBy:[{createdAt:"desc"},{id:"desc"}],select:{balance:true}});const balance=Number(latest?.balance??0);if(input.amount<0&&balance+input.amount<0)throw new CreditError();
  const entry=await tx.creditLedger.create({data:{userId:input.userId,type:input.type,reason:input.reason,amount:input.amount,balance:balance+input.amount,reference:input.reference,idempotencyKey:input.idempotencyKey,metadata:input.metadata??{}},select:{id:true,balance:true}});
  const action=input.amount<0?"credits.consumed":input.reason==="REFUND_REVERSAL"?"credits.reversed":"credits.granted";const details=JSON.stringify({reason:input.reason,amount:input.amount,idempotencyKey:input.idempotencyKey});
  await tx.$executeRaw`INSERT INTO audit_logs(id,user_id,action,resource,resource_id,details) VALUES (${randomUUID()}::uuid,${input.userId}::uuid,${action},'credit_ledger',${entry.id}::uuid,${details}::jsonb)`;return{balance:entry.balance,reused:false};
 });
}
export function consumeCreditsOnce(userId:string,toolId:string,reference:string){const cost=creditCost(toolId);return append({userId,amount:-cost,type:"USAGE",reason:creditReason(toolId),idempotencyKey:reference,reference,metadata:{toolId,policyVersion:"2026-09-provisional-v1"}})}
export const consumeCredits=consumeCreditsOnce;
export function grantSignupCredits(userId:string){return append({userId,amount:PLAN_POLICIES.FREE.creditAllowance,type:"BONUS",reason:"PROMOTIONAL_GRANT",idempotencyKey:"signup-free-onboarding-v1",reference:"signup-bonus",metadata:{provisional:true}})}
export function reverseCredits(input:{userId:string;amount:number;originalReference:string;idempotencyKey:string}){if(input.amount<=0)throw new Error("REVERSAL_AMOUNT_INVALID");return append({userId:input.userId,amount:input.amount,type:"REFUND",reason:"REFUND_REVERSAL",idempotencyKey:input.idempotencyKey,reference:input.originalReference})}
