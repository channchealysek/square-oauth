import crypto from 'node:crypto';
import type { Express } from 'express';
import { encryptString } from '../src/crypto/encryption.js';
import { hashTenantSecret } from '../src/crypto/secrets.js';
import { OAUTH_STATE_TTL_MS, SQUARE_OAUTH_SCOPES } from '../src/domain/squarePolicy.js';
import type { SquarePaymentFacts } from '../src/domain/paymentVerification.js';
import {
  MemoryAuthorizationRepository,
  MemoryOAuthStateRepository,
  MemoryTenantRepository,
} from '../src/repositories/memory.js';
import type { ObtainedTokens, SquareApi, SquareLocationResult } from '../src/square/client.js';
import { createApp } from '../src/app.js';

export class FakeSquare implements SquareApi {
  readonly calls: string[] = [];
  exchangeError: Error | null = null;
  refreshError: Error | null = null;
  revokeError: Error | null = null;
  locations: SquareLocationResult[] = [];
  payment: SquarePaymentFacts | null = null;
  tokens: ObtainedTokens = {
    accessToken: 'EAAAtestAccesstokenValue123456',
    refreshToken: 'EAAAtestRefreshtokenValue123456',
    expiresAt: new Date(Date.now() + 29 * 24 * 60 * 60 * 1000),
    merchantId: 'MERCHANT1',
  };

  async exchangeAuthorizationCode(): Promise<ObtainedTokens> {
    this.calls.push('exchange');
    if (this.exchangeError) {
      throw this.exchangeError;
    }
    return this.tokens;
  }

  async refreshAccessToken(): Promise<ObtainedTokens> {
    this.calls.push('refresh');
    if (this.refreshError) {
      throw this.refreshError;
    }
    return this.tokens;
  }

  async revokeMerchant(): Promise<void> {
    this.calls.push('revokeMerchant');
    if (this.revokeError) {
      throw this.revokeError;
    }
  }

  async revokeSingleAccessToken(): Promise<void> {
    this.calls.push('revokeSingle');
  }

  async listLocations(): Promise<SquareLocationResult[]> {
    this.calls.push('listLocations');
    return this.locations;
  }

  async getPayment(): Promise<SquarePaymentFacts | null> {
    this.calls.push('getPayment');
    return this.payment;
  }
}

export interface TestContext {
  app: Express;
  secret: string;
  otherSecret: string;
  encryptionKey: Buffer;
  tenants: MemoryTenantRepository;
  states: MemoryOAuthStateRepository;
  authorizations: MemoryAuthorizationRepository;
  square: FakeSquare;
}

export async function createTestContext(): Promise<TestContext> {
  const tenants = new MemoryTenantRepository();
  const states = new MemoryOAuthStateRepository();
  const authorizations = new MemoryAuthorizationRepository();
  const square = new FakeSquare();
  const encryptionKey = crypto.randomBytes(32);
  const secret = crypto.randomBytes(32).toString('base64url');
  const otherSecret = crypto.randomBytes(32).toString('base64url');
  const primary = await hashTenantSecret(secret);
  const secondary = await hashTenantSecret(otherSecret);
  await tenants.insert({
    tenantId: 'max-donuts',
    name: 'Max Donuts',
    baseUrl: 'https://maxdonut.channchealysek.com',
    active: true,
    ...primary,
  });
  await tenants.insert({
    tenantId: 'other-donuts',
    name: 'Other Donuts',
    baseUrl: 'https://other.example.com',
    active: true,
    ...secondary,
  });
  const app = createApp({
    config: {
      port: 0,
      mongodbUri: 'mongodb://127.0.0.1:27017/square-oauth-test',
      applicationId: 'sq0idp-test-app',
      applicationSecret: 'test-application-secret-value',
      redirectUri: 'https://square.channchealysek.com/oauth/callback',
      encryptionKey,
      oauthStateTtlMs: OAUTH_STATE_TTL_MS,
      rateLimits: {
        startPerMinute: 10_000,
        callbackPerMinute: 10_000,
        apiPerMinute: 10_000,
      },
    },
    tenants,
    states,
    authorizations,
    square,
    isDatabaseHealthy: () => true,
  });
  return { app, secret, otherSecret, encryptionKey, tenants, states, authorizations, square };
}

export async function connectTestSeller(ctx: TestContext, accessToken = ctx.square.tokens.accessToken): Promise<void> {
  const expiresAt = new Date(Date.now() + 29 * 24 * 60 * 60 * 1000);
  await ctx.authorizations.saveConnected({
    tenantId: 'max-donuts',
    merchantId: 'MERCHANT1',
    environment: 'production',
    authorizationStatus: 'connected',
    accessToken: encryptString(accessToken, ctx.encryptionKey, 'max-donuts'),
    refreshToken: encryptString(ctx.square.tokens.refreshToken ?? 'refresh', ctx.encryptionKey, 'max-donuts'),
    accessTokenExpiresAt: expiresAt,
    accessTokenRefreshedAt: new Date(),
    requestedScopes: [...SQUARE_OAUTH_SCOPES],
    locations: [
      { locationId: 'L1', name: 'Alpha', status: 'ACTIVE', currency: 'USD' },
    ],
    selectedLocationId: 'L1',
    connectedAt: new Date(),
    disconnectedAt: null,
    refreshLockUntil: null,
    refreshLockId: null,
  });
}

export function authHeader(secret: string): { Authorization: string } {
  return { Authorization: `Bearer ${secret}` };
}
