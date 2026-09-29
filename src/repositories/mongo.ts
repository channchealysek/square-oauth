import { fixedEqual } from '../crypto/secrets.js';
import { classifyOAuthState } from '../domain/oauthState.js';
import { DuplicateMerchantError, DuplicateTenantError } from '../domain/errors.js';
import type { LocationChoice } from '../domain/locations.js';
import type { EncryptedBlob } from '../crypto/encryption.js';
import {
  OAuthStateModel,
  SquareAuthorizationModel,
  TenantModel,
} from './models.js';
import type {
  AuthorizationRecord,
  AuthorizationRepository,
  AuthorizationStatus,
  ConsumeResult,
  OAuthStateRepository,
  RefreshedTokenUpdate,
  TenantRecord,
  TenantRepository,
} from './types.js';

interface MongoDuplicateError {
  code: number;
  keyPattern?: Record<string, unknown>;
}

export class MongoTenantRepository implements TenantRepository {
  async findById(tenantId: string): Promise<TenantRecord | null> {
    const doc = await TenantModel.findOne({ tenantId }).lean();
    if (!doc) {
      return null;
    }
    return {
      tenantId: doc.tenantId,
      name: doc.name,
      baseUrl: doc.baseUrl,
      secretSalt: doc.secretSalt,
      secretHash: doc.secretHash,
      active: doc.active,
    };
  }

  async insert(record: TenantRecord): Promise<void> {
    try {
      await TenantModel.create(record);
    } catch (error) {
      if (isDuplicateKey(error)) {
        throw new DuplicateTenantError();
      }
      throw error;
    }
  }

  async replaceSecret(tenantId: string, secretSalt: string, secretHash: string): Promise<boolean> {
    const result = await TenantModel.updateOne({ tenantId }, { $set: { secretSalt, secretHash } });
    return result.matchedCount === 1;
  }
}

export class MongoOAuthStateRepository implements OAuthStateRepository {
  async create(input: {
    stateHash: string;
    tenantId: string;
    returnPath: string;
    now: Date;
    ttlMs: number;
  }): Promise<{ expiresAt: Date }> {
    const expiresAt = new Date(input.now.getTime() + input.ttlMs);
    await OAuthStateModel.create({
      stateHash: input.stateHash,
      tenantId: input.tenantId,
      returnPath: input.returnPath,
      expiresAt,
      consumedAt: null,
    });
    return { expiresAt };
  }

  async consume(stateHash: string, now: Date): Promise<ConsumeResult> {
    const claimed = await OAuthStateModel.findOneAndUpdate(
      { stateHash, consumedAt: null, expiresAt: { $gt: now } },
      { $set: { consumedAt: now } },
      { new: true },
    ).lean();
    if (claimed) {
      if (!fixedEqual(claimed.stateHash, stateHash)) {
        return { ok: false, reason: 'unknown' };
      }
      return { ok: true, tenantId: claimed.tenantId, returnPath: claimed.returnPath };
    }
    const existing = await OAuthStateModel.findOne({ stateHash }).lean();
    if (!existing || !fixedEqual(existing.stateHash, stateHash)) {
      return { ok: false, reason: 'unknown' };
    }
    const classification = classifyOAuthState(
      { consumedAt: existing.consumedAt ?? null, expiresAt: existing.expiresAt },
      now,
    );
    if (classification === 'valid') {
      return { ok: false, reason: 'consumed' };
    }
    return { ok: false, reason: classification };
  }
}

export class MongoAuthorizationRepository implements AuthorizationRepository {
  async findByTenantId(tenantId: string): Promise<AuthorizationRecord | null> {
    const doc = await SquareAuthorizationModel.findOne({ tenantId }).lean();
    return doc ? mapAuthorization(doc) : null;
  }

  async saveConnected(record: AuthorizationRecord): Promise<void> {
    if (record.merchantId) {
      const other = await SquareAuthorizationModel.findOne({
        merchantId: record.merchantId,
        authorizationStatus: 'connected',
        tenantId: { $ne: record.tenantId },
      }).lean();
      if (other) {
        throw new DuplicateMerchantError();
      }
    }
    try {
      await SquareAuthorizationModel.findOneAndUpdate(
        { tenantId: record.tenantId },
        {
          $set: {
            merchantId: record.merchantId,
            environment: 'production',
            authorizationStatus: record.authorizationStatus,
            accessToken: record.accessToken,
            refreshToken: record.refreshToken,
            accessTokenExpiresAt: record.accessTokenExpiresAt,
            accessTokenRefreshedAt: record.accessTokenRefreshedAt,
            requestedScopes: record.requestedScopes,
            locations: record.locations,
            selectedLocationId: record.selectedLocationId,
            connectedAt: record.connectedAt,
            disconnectedAt: record.disconnectedAt,
            refreshLockUntil: null,
            refreshLockId: null,
          },
          $setOnInsert: { tenantId: record.tenantId },
        },
        { upsert: true, new: true, runValidators: true },
      );
    } catch (error) {
      if (isDuplicateKey(error) && isMerchantDuplicate(error)) {
        throw new DuplicateMerchantError();
      }
      throw error;
    }
  }

  async tryAcquireRefreshLock(
    tenantId: string,
    lockId: string,
    until: Date,
    now: Date,
  ): Promise<AuthorizationRecord | null> {
    const doc = await SquareAuthorizationModel.findOneAndUpdate(
      {
        tenantId,
        authorizationStatus: 'connected',
        $or: [
          { refreshLockUntil: null },
          { refreshLockUntil: { $lte: now } },
          { refreshLockUntil: { $exists: false } },
        ],
      },
      { $set: { refreshLockUntil: until, refreshLockId: lockId } },
      { new: true },
    ).lean();
    return doc ? mapAuthorization(doc) : null;
  }

  async saveRefreshedTokens(tenantId: string, lockId: string, update: RefreshedTokenUpdate): Promise<void> {
    const result = await SquareAuthorizationModel.updateOne(
      { tenantId, refreshLockId: lockId, authorizationStatus: 'connected' },
      {
        $set: {
          accessToken: update.accessToken,
          refreshToken: update.refreshToken,
          accessTokenExpiresAt: update.accessTokenExpiresAt,
          accessTokenRefreshedAt: update.accessTokenRefreshedAt,
        },
      },
    );
    if (result.matchedCount !== 1) {
      throw new Error('refresh lock lost');
    }
  }

  async releaseRefreshLock(tenantId: string, lockId: string): Promise<void> {
    await SquareAuthorizationModel.updateOne(
      { tenantId, refreshLockId: lockId },
      { $set: { refreshLockUntil: null, refreshLockId: null } },
    );
  }

  async markRevoked(tenantId: string, now: Date): Promise<void> {
    await wipe(tenantId, 'revoked', now);
  }

  async clearAuthorization(tenantId: string, now: Date): Promise<void> {
    await wipe(tenantId, 'disconnected', now);
  }

  async saveLocations(
    tenantId: string,
    locations: LocationChoice[],
    selectedLocationId: string | null,
  ): Promise<void> {
    await SquareAuthorizationModel.updateOne(
      { tenantId, authorizationStatus: 'connected' },
      { $set: { locations, selectedLocationId } },
    );
  }
}

async function wipe(tenantId: string, status: AuthorizationStatus, now: Date): Promise<void> {
  await SquareAuthorizationModel.updateOne(
    { tenantId },
    {
      $set: {
        authorizationStatus: status,
        accessToken: null,
        refreshToken: null,
        accessTokenExpiresAt: null,
        merchantId: null,
        locations: [],
        selectedLocationId: null,
        refreshLockUntil: null,
        refreshLockId: null,
        disconnectedAt: now,
      },
    },
  );
}

function mapAuthorization(doc: {
  tenantId: string;
  merchantId?: string | null;
  environment: string;
  authorizationStatus: AuthorizationStatus;
  accessToken?: EncryptedBlob | null;
  refreshToken?: EncryptedBlob | null;
  accessTokenExpiresAt?: Date | null;
  accessTokenRefreshedAt?: Date | null;
  requestedScopes: string[];
  locations: Iterable<{
    locationId: string;
    name: string;
    status: string;
    currency?: string | null;
  }>;
  selectedLocationId?: string | null;
  connectedAt?: Date | null;
  disconnectedAt?: Date | null;
  refreshLockUntil?: Date | null;
  refreshLockId?: string | null;
}): AuthorizationRecord {
  return {
    tenantId: doc.tenantId,
    merchantId: doc.merchantId ?? null,
    environment: 'production',
    authorizationStatus: doc.authorizationStatus,
    accessToken: doc.accessToken ?? null,
    refreshToken: doc.refreshToken ?? null,
    accessTokenExpiresAt: doc.accessTokenExpiresAt ?? null,
    accessTokenRefreshedAt: doc.accessTokenRefreshedAt ?? null,
    requestedScopes: doc.requestedScopes,
    locations: Array.from(doc.locations).map((location) => ({
      locationId: location.locationId,
      name: location.name,
      status: location.status,
      currency: location.currency ?? null,
    })),
    selectedLocationId: doc.selectedLocationId ?? null,
    connectedAt: doc.connectedAt ?? null,
    disconnectedAt: doc.disconnectedAt ?? null,
    refreshLockUntil: doc.refreshLockUntil ?? null,
    refreshLockId: doc.refreshLockId ?? null,
  };
}

function isDuplicateKey(error: unknown): error is MongoDuplicateError {
  return Boolean(error && typeof error === 'object' && (error as MongoDuplicateError).code === 11000);
}

function isMerchantDuplicate(error: MongoDuplicateError): boolean {
  return Boolean(error.keyPattern && 'merchantId' in error.keyPattern);
}
