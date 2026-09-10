export type PlanCode = "FREE" | "PRO";
export type Entitlements = Readonly<{ maxFileSizeBytes:number; maxPagesPerFile:number; maxJobsPerDay:number; maxJobsPerMonth:number; maxConcurrentJobs:number; creditAllowance:number; maxAiCreditsPerRequest:number; maxOcrPagesPerMonth:number; aiAccess:boolean; toolAccess:readonly string[]|"*"; processingPriority:"standard"|"high"; retentionDays:number; proFeatures:readonly string[] }>;
export const MONETIZATION_POLICY_VERSION = "2026-09-provisional-v1";
export const PLAN_POLICIES: Readonly<Record<PlanCode, Entitlements>> = {
 FREE:{maxFileSizeBytes:25*1024*1024,maxPagesPerFile:100,maxJobsPerDay:20,maxJobsPerMonth:300,maxConcurrentJobs:2,creditAllowance:20,maxAiCreditsPerRequest:5,maxOcrPagesPerMonth:100,aiAccess:true,toolAccess:"*",processingPriority:"standard",retentionDays:7,proFeatures:[]},
 PRO:{maxFileSizeBytes:100*1024*1024,maxPagesPerFile:500,maxJobsPerDay:200,maxJobsPerMonth:3000,maxConcurrentJobs:8,creditAllowance:500,maxAiCreditsPerRequest:25,maxOcrPagesPerMonth:2000,aiAccess:true,toolAccess:"*",processingPriority:"high",retentionDays:30,proFeatures:["advanced-controls","priority-processing"]},
};
export function effectiveToolLimits(tool:{limits:{maxBytes:number;maxPages?:number;maxFiles:number}},plan:Entitlements){return{maxBytes:Math.min(tool.limits.maxBytes,plan.maxFileSizeBytes),maxPages:Math.min(tool.limits.maxPages??plan.maxPagesPerFile,plan.maxPagesPerFile),maxFiles:tool.limits.maxFiles}}
export function planCanUseTool(plan:Entitlements,toolId:string){return plan.toolAccess==="*"||plan.toolAccess.includes(toolId)}
