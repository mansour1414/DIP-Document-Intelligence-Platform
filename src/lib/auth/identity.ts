const EMAIL_PATTERN = /^\S+@\S+\.\S+$/;

export class AuthIdentityError extends Error {
  readonly code = "AUTH_EMAIL_INVALID";

  constructor() {
    super("Authentication email is invalid");
  }
}

export function normalizeAuthEmail(value: unknown) {
  const email = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!email || email.length > 255 || !EMAIL_PATTERN.test(email)) throw new AuthIdentityError();
  return email;
}
