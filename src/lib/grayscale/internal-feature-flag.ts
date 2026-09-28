export const INTERNAL_GRAYSCALE_FEATURE_FLAG = "DIP_INTERNAL_GRAYSCALE_ENABLED" as const;
export const GRAYSCALE_LICENSING_GATE_FLAG = "DIP_GRAYSCALE_LICENSING_GATE_APPROVED" as const;

export type InternalGrayscaleGate = {
  requested: boolean;
  licensingApproved: boolean;
  enabled: boolean;
  blockedBy: "feature_off" | "licensing_not_approved" | null;
};

function isExplicitlyEnabled(value: string | undefined): boolean {
  return value === "true";
}

/**
 * Internal-only foundation for G1-A. This module does not register, dispatch, or
 * expose a Grayscale tool. The runtime stays fail-closed until both the internal
 * request and the separately recorded Licensing Gate approval are explicit.
 */
export function resolveInternalGrayscaleGate(
  env: Readonly<Record<string, string | undefined>> = process.env,
): InternalGrayscaleGate {
  const requested = isExplicitlyEnabled(env[INTERNAL_GRAYSCALE_FEATURE_FLAG]);
  const licensingApproved = isExplicitlyEnabled(env[GRAYSCALE_LICENSING_GATE_FLAG]);
  const enabled = requested && licensingApproved;

  return {
    requested,
    licensingApproved,
    enabled,
    blockedBy: enabled ? null : requested ? "licensing_not_approved" : "feature_off",
  };
}
