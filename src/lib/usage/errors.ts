export type MonetizationErrorCode="PLAN_LIMIT_EXCEEDED"|"FILE_SIZE_PLAN_LIMIT_EXCEEDED"|"PAGE_LIMIT_EXCEEDED"|"DAILY_JOB_LIMIT_EXCEEDED"|"MONTHLY_JOB_LIMIT_EXCEEDED"|"CONCURRENCY_LIMIT_EXCEEDED"|"INSUFFICIENT_CREDITS"|"PRO_FEATURE_REQUIRED";
export class MonetizationError extends Error{constructor(public readonly code:MonetizationErrorCode,message=code){super(message)}}
