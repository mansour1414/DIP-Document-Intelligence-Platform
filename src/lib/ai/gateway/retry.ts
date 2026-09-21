import { UnrecoverableError } from "bullmq";
import { AiGatewayError } from "./types";

export function toAiQueueError(error: unknown): Error {
  if (error instanceof AiGatewayError && !error.retryable) return new UnrecoverableError(error.message);
  return error instanceof Error ? error : new Error("AI processing failed");
}

export function isUnrecoverableAiQueueError(error: Error) {
  return error instanceof UnrecoverableError || error.name === "UnrecoverableError";
}
