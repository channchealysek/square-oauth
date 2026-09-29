import { fixedEqual } from '../crypto/secrets.js';
import { classifyOAuthState } from '../domain/oauthState.js';
import { DuplicateMerchantError, DuplicateTenantError } from '../domain/errors.js';
import type {
  AuthorizationRecord,
  AuthorizationRepository,
  ConsumeResult,
  OAuthStateRecord,
  OAuthStateRepository,
  RefreshedTokenUpdate,
  TenantRecord,
  TenantRepository,
} from './types.js';
import type { LocationChoice } from '../domain/locations.js';

export class MemoryTenantRepository implements TenantRepository {
  private readonly records = new Map<string, TenantRecord>();

  async findById(tenantId: string): Promise<TenantRecord | null> {
    const record = this.records.get(tenantId);
    return record ? { ...record } : null;
  }

  async insert(record: TenantRecord): Promise<void> {
    if (this.records.has(record.tenantId)) {
      throw new DuplicateTenantError();
    }
    this.records.set(record.tenantId, { ...record });
  }

  async replaceSecret(tenantId: string, secretSalt: string, secretHash: string): Promise<boolean> {
    const record = this.records.get(tenantId);
    if (!record) {
      return false;
    }
    record.secretSalt = secretSalt;
    record.secretHash = secretHash;
    return true;
  }
}

export class MemoryOAuthStateRepository implements OAuthStateRepository {
  private readonly records = new Map<string, OAuthStateRecord>();

  async create(input: {
    stateHash: string;
    tenantId: string;
    returnPath: string;
    now: Date;
    ttlMs: number;
  }): Promise<{ expiresAt: Date }> {
    const expiresAt = new Date(input.now.getTime() + input.ttlMs);
    this.records.set(input.stateHash, {
      stateHash: input.stateHash,
      tenantId: input.tenantId,
      returnPath: input.returnPath,
      expiresAt,
      consumedAt: null,
    });
    return { expiresAt };
  }

  async consume(stateHash: string, now: Date): Promise<ConsumeResult> {
    const record = this.records.get(stateHash);
    if (!record || !fixedEqual(record.stateHash, stateHash)) {
      return { ok: false, reason: 'unknown' };
    }
    const classification = classifyOAuthState(record, now);
    if (classification === 'expired' || classification === 'consumed' || classification === 'unknown') {
      return { ok: false, reason: classification };
    }
    record.consumedAt = now;
    return { ok: true, tenantId: record.tenantId, returnPath: record.returnPath };
  }
}

export class MemoryAuthorizationRepository implements AuthorizationRepository {
  private readonly records = new Map<string, AuthorizationRecord>();

  async findByTenantId(tenantId: string): Promise<AuthorizationRecord | null> {
    const record = this.records.get(tenantId);
    return record ? structuredClone(record) : null;
  }

  async saveConnected(record: AuthorizationRecord): Promise<void> {
    if (record.merchantId && record.authorizationStatus === 'connected') {
      for (const existing of this.records.values()) {
        if (
          existing.tenantId !== record.tenantId &&
          existing.authorizationStatus === 'connected' &&
          existing.merchantId === record.merchantId
        ) {
          throw new DuplicateMerchantError();
        }
      }
    }
    this.records.set(record.tenantId, structuredClone(record));
  }

  async tryAcquireRefreshLock(
    tenantId: string,
    lockId: string,
    until: Date,
    now: Date,
  ): Promise<AuthorizationRecord | null> {
    const record = this.records.get(tenantId);
    if (!record || record.authorizationStatus !== 'connected') {
      return null;
    }
    if (record.refreshLockUntil && record.refreshLockUntil.getTime() > now.getTime()) {
      return null;
    }
    record.refreshLockUntil = until;
    record.refreshLockId = lockId;
    return structuredClone(record);
  }

  async saveRefreshedTokens(tenantId: string, lockId: string, update: RefreshedTokenUpdate): Promise<void> {
    const record = this.records.get(tenantId);
    if (!record || record.refreshLockId !== lockId || record.authorizationStatus !== 'connected') {
      throw new Error('refresh lock lost');
    }
    record.accessToken = update.accessToken;
    record.refreshToken = update.refreshToken;
    record.accessTokenExpiresAt = update.accessTokenExpiresAt;
    record.accessTokenRefreshedAt = update.accessTokenRefreshedAt;
  }

  async releaseRefreshLock(tenantId: string, lockId: string): Promise<void> {
    const record = this.records.get(tenantId);
    if (!record || record.refreshLockId !== lockId) {
      return;
    }
    record.refreshLockUntil = null;
    record.refreshLockId = null;
  }

  async markRevoked(tenantId: string, now: Date): Promise<void> {
    const record = this.records.get(tenantId);
    if (!record) {
      return;
    }
    wipeSecrets(record, 'revoked', now);
  }

  async clearAuthorization(tenantId: string, now: Date): Promise<void> {
    const record = this.records.get(tenantId);
    if (!record) {
      return;
    }
    wipeSecrets(record, 'disconnected', now);
  }

  async saveLocations(
    tenantId: string,
    locations: LocationChoice[],
    selectedLocationId: string | null,
  ): Promise<void> {
    const record = this.records.get(tenantId);
    if (!record || record.authorizationStatus !== 'connected') {
      return;
    }
    record.locations = structuredClone(locations);
    record.selectedLocationId = selectedLocationId;
  }
}

function wipeSecrets(
  record: AuthorizationRecord,
  status: 'revoked' | 'disconnected',
  now: Date,
): void {
  record.authorizationStatus = status;
  record.accessToken = null;
  record.refreshToken = null;
  record.accessTokenExpiresAt = null;
  record.merchantId = null;
  record.locations = [];
  record.selectedLocationId = null;
  record.refreshLockUntil = null;
  record.refreshLockId = null;
  record.disconnectedAt = now;
}
