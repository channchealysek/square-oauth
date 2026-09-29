import type { EncryptedBlob } from '../crypto/encryption.js';
import type { LocationChoice } from '../domain/locations.js';

export type AuthorizationStatus = 'connected' | 'disconnected' | 'revoked';

export interface TenantRecord {
  tenantId: string;
  name: string;
  baseUrl: string;
  secretSalt: string;
  secretHash: string;
  active: boolean;
}

export interface TenantRepository {
  findById(tenantId: string): Promise<TenantRecord | null>;
  insert(record: TenantRecord): Promise<void>;
  replaceSecret(tenantId: string, secretSalt: string, secretHash: string): Promise<boolean>;
}

export interface OAuthStateRecord {
  stateHash: string;
  tenantId: string;
  returnPath: string;
  expiresAt: Date;
  consumedAt: Date | null;
}

export type ConsumeResult =
  | { ok: true; tenantId: string; returnPath: string }
  | { ok: false; reason: 'unknown' | 'expired' | 'consumed' };

export interface OAuthStateRepository {
  create(input: {
    stateHash: string;
    tenantId: string;
    returnPath: string;
    now: Date;
    ttlMs: number;
  }): Promise<{ expiresAt: Date }>;
  consume(stateHash: string, now: Date): Promise<ConsumeResult>;
}

export interface AuthorizationRecord {
  tenantId: string;
  merchantId: string | null;
  environment: 'production';
  authorizationStatus: AuthorizationStatus;
  accessToken: EncryptedBlob | null;
  refreshToken: EncryptedBlob | null;
  accessTokenExpiresAt: Date | null;
  accessTokenRefreshedAt: Date | null;
  requestedScopes: string[];
  locations: LocationChoice[];
  selectedLocationId: string | null;
  connectedAt: Date | null;
  disconnectedAt: Date | null;
  refreshLockUntil: Date | null;
  refreshLockId: string | null;
}

export interface RefreshedTokenUpdate {
  accessToken: EncryptedBlob;
  refreshToken: EncryptedBlob;
  accessTokenExpiresAt: Date;
  accessTokenRefreshedAt: Date;
}

export interface AuthorizationRepository {
  findByTenantId(tenantId: string): Promise<AuthorizationRecord | null>;
  saveConnected(record: AuthorizationRecord): Promise<void>;
  tryAcquireRefreshLock(
    tenantId: string,
    lockId: string,
    until: Date,
    now: Date,
  ): Promise<AuthorizationRecord | null>;
  saveRefreshedTokens(tenantId: string, lockId: string, update: RefreshedTokenUpdate): Promise<void>;
  releaseRefreshLock(tenantId: string, lockId: string): Promise<void>;
  markRevoked(tenantId: string, now: Date): Promise<void>;
  clearAuthorization(tenantId: string, now: Date): Promise<void>;
  saveLocations(tenantId: string, locations: LocationChoice[], selectedLocationId: string | null): Promise<void>;
}
