export class OperationTimeoutError extends Error {
  readonly code = "PROCESSING_TIMEOUT";
  constructor(public readonly operation: string, public readonly timeoutMs: number) {
    super(`${operation} exceeded its ${timeoutMs}ms execution limit.`);
  }
}

export async function withTimeout<T>(operation: string, timeoutMs: number, work: Promise<T>, onTimeout?: () => void | Promise<void>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(async () => {
      try { await onTimeout?.(); } finally { reject(new OperationTimeoutError(operation, timeoutMs)); }
    }, timeoutMs);
    timer.unref?.();
  });
  try { return await Promise.race([work, timeout]); }
  finally { if (timer) clearTimeout(timer); }
}

