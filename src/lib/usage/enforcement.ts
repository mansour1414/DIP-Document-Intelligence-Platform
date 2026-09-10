import { getToolDefinition } from "@/lib/tools/registry";
import { consumeCreditsOnce } from "@/lib/billing/credits";
import { creditCost } from "@/lib/billing/credit-policy";
import { effectiveToolLimits, planCanUseTool } from "@/lib/entitlements/policy";
import { resolvePlan } from "@/lib/entitlements/service";
import { MonetizationError } from "./errors";
import { logger } from "@/lib/logging";
import { withTenant } from "@/lib/db/tenant";
import { recordMetric } from "@/lib/observability/metrics";

const running=["QUEUED","RUNNING","RETRYING"] as const;
export async function enforceJobCreation(input:{userId:string;toolId:string;idempotencyKey:string;files:readonly {size:number;pageCount?:number}[];options?:Record<string,unknown>;correlationId?:string}){
 const tool=getToolDefinition(input.toolId);const resolved=await resolvePlan(input.userId);const limits=effectiveToolLimits(tool,resolved.entitlements);
 if(!planCanUseTool(resolved.entitlements,input.toolId))throw new MonetizationError("PLAN_LIMIT_EXCEEDED");
 if(tool.aiFlag&&!resolved.entitlements.aiAccess)throw new MonetizationError("PRO_FEATURE_REQUIRED");
 if(input.options?.advanced===true&&!resolved.entitlements.proFeatures.includes("advanced-controls"))throw new MonetizationError("PRO_FEATURE_REQUIRED");
 if(input.files.some(f=>f.size>limits.maxBytes))throw new MonetizationError("FILE_SIZE_PLAN_LIMIT_EXCEEDED");
 if(input.files.some(f=>(f.pageCount??0)>limits.maxPages))throw new MonetizationError("PAGE_LIMIT_EXCEEDED");
 const now=new Date(),day=new Date(now);day.setUTCHours(0,0,0,0);const month=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),1));
 await withTenant({userId:input.userId},async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`usage:${input.userId}`},0))`;
  const prior=await tx.usageEvent.findUnique({where:{userId_kind_reference:{userId:input.userId,kind:"job.created",reference:input.idempotencyKey}}});if(prior)return;
  const [daily,monthly,concurrent]=await Promise.all([tx.usageEvent.aggregate({_sum:{quantity:true},where:{userId:input.userId,kind:"job.created",occurredAt:{gte:day}}}),tx.usageEvent.aggregate({_sum:{quantity:true},where:{userId:input.userId,kind:"job.created",occurredAt:{gte:month}}}),tx.job.count({where:{requesterId:input.userId,status:{in:[...running]}}})]);
  if((daily._sum.quantity??0)>=resolved.entitlements.maxJobsPerDay)throw new MonetizationError("DAILY_JOB_LIMIT_EXCEEDED");
  if((monthly._sum.quantity??0)>=resolved.entitlements.maxJobsPerMonth)throw new MonetizationError("MONTHLY_JOB_LIMIT_EXCEEDED");
  if(concurrent>=resolved.entitlements.maxConcurrentJobs)throw new MonetizationError("CONCURRENCY_LIMIT_EXCEEDED");
  await tx.usageEvent.create({data:{userId:input.userId,kind:"job.created",reference:input.idempotencyKey,metadata:{toolId:input.toolId,plan:resolved.code}}});
 });
 const cost=creditCost(input.toolId);if(tool.aiFlag&&cost>resolved.entitlements.maxAiCreditsPerRequest)throw new MonetizationError("PLAN_LIMIT_EXCEEDED");
 try{await consumeCreditsOnce(input.userId,input.toolId,`job:${input.toolId}:${input.idempotencyKey}`)}catch(error){if(error instanceof Error&&error.message==="INSUFFICIENT_CREDITS")throw new MonetizationError("INSUFFICIENT_CREDITS");throw error}
 recordMetric("credits_consumed",cost,"count",{tool_id:input.toolId});
 logger.info("monetization.job_authorized",{user_id:input.userId,tool_id:input.toolId,plan:resolved.code,cost,correlation_id:input.correlationId});return resolved;
}

export async function usageSummary(userId:string){const resolved=await resolvePlan(userId);const now=new Date(),day=new Date(now);day.setUTCHours(0,0,0,0);const month=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),1));return withTenant({userId},async tx=>{const [daily,monthly,concurrent]=await Promise.all([tx.usageEvent.aggregate({_sum:{quantity:true},where:{userId,kind:"job.created",occurredAt:{gte:day}}}),tx.usageEvent.aggregate({_sum:{quantity:true},where:{userId,kind:"job.created",occurredAt:{gte:month}}}),tx.job.count({where:{requesterId:userId,status:{in:[...running]}}})]);return{plan:resolved.code,subscriptionStatus:resolved.subscriptionStatus,limits:resolved.entitlements,usage:{dailyJobs:daily._sum.quantity??0,monthlyJobs:monthly._sum.quantity??0,concurrentJobs:concurrent}}})}
