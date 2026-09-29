export type OAuthStateClassification = 'valid' | 'unknown' | 'expired' | 'consumed';

export function classifyOAuthState(
  record: { consumedAt: Date | null; expiresAt: Date } | null,
  now: Date,
): OAuthStateClassification {
  if (!record) {
    return 'unknown';
  }
  if (record.consumedAt) {
    return 'consumed';
  }
  if (record.expiresAt.getTime() <= now.getTime()) {
    return 'expired';
  }
  return 'valid';
}
