import type { SubscriptionStatus } from "@prisma/client";
const transitions:Record<SubscriptionStatus,readonly SubscriptionStatus[]>={TRIALING:["ACTIVE","CANCELLED","EXPIRED"],ACTIVE:["PAST_DUE","CANCELLED","EXPIRED"],PAST_DUE:["ACTIVE","CANCELLED","EXPIRED"],CANCELLED:["ACTIVE","EXPIRED"],EXPIRED:[]};
export function assertSubscriptionTransition(from:SubscriptionStatus,to:SubscriptionStatus){if(from!==to&&!transitions[from].includes(to))throw new Error("INVALID_SUBSCRIPTION_TRANSITION")}
