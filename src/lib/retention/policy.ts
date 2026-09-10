export type RetentionCandidate = { id: string; createdAt: Date; hasActiveJob: boolean; alreadyDeleted: boolean };

export function selectExpiredCandidates(candidates: RetentionCandidate[], now: Date, retentionDays: number) {
  if (!Number.isInteger(retentionDays) || retentionDays < 1) throw new Error("RETENTION_POLICY_INVALID");
  const cutoff = now.getTime() - retentionDays * 86_400_000;
  return candidates.filter((candidate) => !candidate.alreadyDeleted && !candidate.hasActiveJob && candidate.createdAt.getTime() < cutoff);
}

export function selectOrphans<T extends { fileReferenceCount: number; alreadyDeleted: boolean }>(objects: T[]) {
  return objects.filter((object) => object.fileReferenceCount === 0 && !object.alreadyDeleted);
}

