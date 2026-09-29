/**
 * Scopes requested from the seller. Names verified against Square's OAuth
 * permissions reference and the Mobile Payments SDK requirements:
 * MERCHANT_PROFILE_READ, PAYMENTS_READ, PAYMENTS_WRITE,
 * PAYMENTS_WRITE_IN_PERSON, DEVICE_CREDENTIAL_MANAGEMENT.
 *
 * ObtainToken does not echo granted scopes. These are the scopes this
 * service requested and recorded at authorization time.
 */
export const SQUARE_OAUTH_SCOPES = [
  'MERCHANT_PROFILE_READ',
  'PAYMENTS_READ',
  'PAYMENTS_WRITE',
  'PAYMENTS_WRITE_IN_PERSON',
  'DEVICE_CREDENTIAL_MANAGEMENT',
] as const;

export const SQUARE_API_VERSION = '2026-09-16';
export const SQUARE_PRODUCTION_ORIGIN = 'https://connect.squareup.com';

/** Square access tokens last 30 days. Renew once fewer than 23 days remain (~7 days old). */
export const ACCESS_TOKEN_REFRESH_REMAINING_MS = 23 * 24 * 60 * 60 * 1000;

export const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

export function needsAccessTokenRefresh(expiresAt: Date | null, now: Date): boolean {
  if (!expiresAt) {
    return true;
  }
  return expiresAt.getTime() - now.getTime() <= ACCESS_TOKEN_REFRESH_REMAINING_MS;
}
