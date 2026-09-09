/** Provider-neutral billing seam. Attach Stripe checkout/webhooks here after keys are configured. */
export type BillingCheckout = { userId: string; plan: "FREE" | "PRO" | "BUSINESS"; successUrl: string; cancelUrl: string };

export async function createBillingCheckout(_input: BillingCheckout): Promise<{ url: string }> {
  void _input;
  throw new Error("BILLING_NOT_CONFIGURED");
}
