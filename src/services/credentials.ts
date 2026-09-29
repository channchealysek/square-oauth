import crypto from 'node:crypto';
import { decryptString, encryptString, type EncryptedBlob } from '../crypto/encryption.js';
import { HttpError } from '../domain/errors.js';
import { needsAccessTokenRefresh } from '../domain/squarePolicy.js';
import type { AuthorizationRecord, AuthorizationRepository } from '../repositories/types.js';
import { SquareRequestError, type ObtainedTokens, type SquareApi } from '../square/client.js';
import { logger } from '../logger.js';

const LOCK_MS = 15_000;
const WAIT_SLICE_MS = 200;
const MAX_WAIT_MS = 10_000;

export interface SellerAccess {
  accessToken: string;
  merchantId: string;
  expiresAt: Date;
  locationId: string | null;
}

export interface CredentialDependencies {
  encryptionKey: Buffer;
  authorizations: AuthorizationRepository;
  square: SquareApi;
  now: () => Date;
}

export async function getSellerAccess(deps: CredentialDependencies, tenantId: string): Promise<SellerAccess> {
  const started = Date.now();
  for (;;) {
    const now = deps.now();
    const record = await requireConnected(deps.authorizations, tenantId);
    if (!needsAccessTokenRefresh(record.accessTokenExpiresAt, now)) {
      return decryptAccess(deps.encryptionKey, record);
    }
    const lockId = crypto.randomUUID();
    const locked = await deps.authorizations.tryAcquireRefreshLock(
      tenantId,
      lockId,
      new Date(now.getTime() + LOCK_MS),
      now,
    );
    if (!locked) {
      if (Date.now() - started > MAX_WAIT_MS) {
        throw new HttpError(503, 'refresh_busy', 'Square authorization refresh is already in progress. Retry shortly.');
      }
      await sleep(WAIT_SLICE_MS);
      continue;
    }
    try {
      const current = await requireConnected(deps.authorizations, tenantId);
      if (!needsAccessTokenRefresh(current.accessTokenExpiresAt, deps.now())) {
        return decryptAccess(deps.encryptionKey, current);
      }
      const refreshToken = decryptField(deps.encryptionKey, current.refreshToken, tenantId);
      let obtained: ObtainedTokens;
      try {
        obtained = await deps.square.refreshAccessToken(refreshToken);
      } catch (error) {
        if (error instanceof SquareRequestError && error.authorizationEnded) {
          await deps.authorizations.markRevoked(tenantId, deps.now());
          throw new HttpError(
            409,
            'authorization_revoked',
            'Square authorization expired or was revoked. Connect the Square account again.',
          );
        }
        logger.warn({ tenantId, name: error instanceof Error ? error.name : 'error' }, 'square token refresh failed');
        throw new HttpError(502, 'square_unavailable', 'Square could not refresh the seller authorization.');
      }
      if (!current.merchantId || obtained.merchantId !== current.merchantId) {
        await deps.square.revokeSingleAccessToken(obtained.accessToken).catch(() => undefined);
        throw new HttpError(
          409,
          'merchant_mismatch',
          'Square returned a different merchant than the one connected to this store.',
        );
      }
      const expiresAt = obtained.expiresAt;
      await deps.authorizations.saveRefreshedTokens(tenantId, lockId, {
        accessToken: encryptString(obtained.accessToken, deps.encryptionKey, tenantId),
        refreshToken: encryptString(obtained.refreshToken ?? refreshToken, deps.encryptionKey, tenantId),
        accessTokenExpiresAt: expiresAt,
        accessTokenRefreshedAt: deps.now(),
      });
      return {
        accessToken: obtained.accessToken,
        merchantId: current.merchantId,
        expiresAt,
        locationId: current.selectedLocationId,
      };
    } finally {
      await deps.authorizations.releaseRefreshLock(tenantId, lockId);
    }
  }
}

export function requireSelectedLocation(access: SellerAccess): SellerAccess & { locationId: string } {
  if (!access.locationId) {
    throw new HttpError(409, 'location_not_selected', 'No active Square location is selected.');
  }
  return access as SellerAccess & { locationId: string };
}

async function requireConnected(
  authorizations: AuthorizationRepository,
  tenantId: string,
): Promise<AuthorizationRecord & { accessToken: EncryptedBlob; refreshToken: EncryptedBlob; merchantId: string }> {
  const record = await authorizations.findByTenantId(tenantId);
  if (record?.authorizationStatus === 'revoked') {
    throw new HttpError(409, 'authorization_revoked', 'Square authorization was revoked. Connect the Square account again.');
  }
  if (
    !record ||
    record.authorizationStatus !== 'connected' ||
    !record.accessToken ||
    !record.refreshToken ||
    !record.merchantId
  ) {
    throw new HttpError(409, 'not_connected', 'This store has not connected a Square account.');
  }
  return {
    ...record,
    accessToken: record.accessToken,
    refreshToken: record.refreshToken,
    merchantId: record.merchantId,
  };
}

function decryptAccess(key: Buffer, record: AuthorizationRecord): SellerAccess {
  if (!record.accessToken || !record.merchantId || !record.accessTokenExpiresAt) {
    throw new HttpError(409, 'not_connected', 'This store has not connected a Square account.');
  }
  return {
    accessToken: decryptField(key, record.accessToken, record.tenantId),
    merchantId: record.merchantId,
    expiresAt: record.accessTokenExpiresAt,
    locationId: record.selectedLocationId,
  };
}

function decryptField(key: Buffer, blob: NonNullable<AuthorizationRecord['accessToken']>, tenantId: string): string {
  try {
    return decryptString(blob, key, tenantId);
  } catch {
    throw new HttpError(
      409,
      'authorization_unreadable',
      'Stored Square credentials could not be decrypted. Check the encryption key or connect the Square account again.',
    );
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
