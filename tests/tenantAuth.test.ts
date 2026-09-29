import crypto from 'node:crypto';
import request from 'supertest';
import { beforeAll, describe, expect, it } from 'vitest';
import { loadServerConfig } from '../src/config.js';
import { generateTenantSecret, hashTenantSecret, verifyTenantSecret } from '../src/crypto/secrets.js';
import { isTenantId, normalizeBaseUrl } from '../src/domain/urls.js';
import { SQUARE_OAUTH_SCOPES } from '../src/domain/squarePolicy.js';
import { authHeader, createTestContext, type TestContext } from './helpers.js';

describe('tenant secrets', () => {
  it('stores a verifier that matches only the original secret', async () => {
    const secret = generateTenantSecret();
    const stored = await hashTenantSecret(secret);
    expect(stored.secretHash).not.toContain(secret);
    expect(await verifyTenantSecret(secret, stored.secretSalt, stored.secretHash)).toBe(true);
    expect(await verifyTenantSecret(generateTenantSecret(), stored.secretSalt, stored.secretHash)).toBe(false);
  });

  it('accepts only https tenant base URLs and lowercase tenant ids', () => {
    expect(normalizeBaseUrl('https://maxdonut.channchealysek.com/')).toBe('https://maxdonut.channchealysek.com');
    expect(() => normalizeBaseUrl('http://maxdonut.channchealysek.com')).toThrow(/https/);
    expect(() => normalizeBaseUrl('https://user:pass@maxdonut.channchealysek.com')).toThrow(/credentials/);
    expect(isTenantId('max-donuts')).toBe(true);
    expect(isTenantId('Max-Donuts')).toBe(false);
  });
});

describe('tenant authentication', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
  });

  it('rejects missing and wrong credentials', async () => {
    const missing = await request(ctx.app).post('/api/tenants/max-donuts/oauth/start').send({});
    expect(missing.status).toBe(401);
    const wrong = await request(ctx.app)
      .post('/api/tenants/max-donuts/oauth/start')
      .set(authHeader(ctx.otherSecret))
      .send({});
    expect(wrong.status).toBe(401);
    expect(wrong.body).toEqual({ error: 'unauthorized', message: 'Tenant authentication failed' });
  });

  it('lets a tenant start OAuth only for itself', async () => {
    const response = await request(ctx.app)
      .post('/api/tenants/max-donuts/oauth/start')
      .set(authHeader(ctx.secret))
      .send({ returnPath: '/admin/square' });
    expect(response.status).toBe(200);
    expect(response.body.state).toBeUndefined();
    expect(response.body.authorizationUrl).toContain('https://connect.squareup.com/oauth2/authorize?');
    expect(response.body.authorizationUrl).toContain('session=false');
    expect(response.body.authorizationUrl).not.toContain('squareupsandbox');
    expect(response.body.authorizationUrl).not.toContain('test-application-secret-value');
    for (const scope of SQUARE_OAUTH_SCOPES) {
      expect(response.body.authorizationUrl).toContain(scope);
    }
    const other = await request(ctx.app)
      .get('/api/tenants/other-donuts/square/status')
      .set(authHeader(ctx.secret));
    expect(other.status).toBe(401);
  });

  it('returns connection status without seller tokens', async () => {
    const response = await request(ctx.app)
      .get('/api/tenants/max-donuts/square/status')
      .set(authHeader(ctx.secret));
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      connected: false,
      merchantId: null,
      locationId: null,
      environment: 'production',
      authorizationStatus: 'disconnected',
    });
    expect(response.body).not.toHaveProperty('accessToken');
    expect(response.body).not.toHaveProperty('refreshToken');
    expect(response.body.expiresAt).toBeNull();
    expect(JSON.stringify(response.body)).not.toMatch(/refreshToken|secretHash|EAAA|sq0csp-/);
  });

  it('requires the tenant secret for status and rejects a disabled tenant', async () => {
    const anonymous = await request(ctx.app).get('/api/tenants/max-donuts/square/status');
    expect(anonymous.status).toBe(401);
    const secret = generateTenantSecret();
    const stored = await hashTenantSecret(secret);
    await ctx.tenants.insert({
      tenantId: 'paused-donuts',
      name: 'Paused',
      baseUrl: 'https://paused.example.com',
      active: false,
      ...stored,
    });
    const paused = await request(ctx.app)
      .get('/api/tenants/paused-donuts/square/status')
      .set(authHeader(secret));
    expect(paused.status).toBe(403);
    expect(paused.body.error).toBe('tenant_inactive');
  });
});

describe('server config', () => {
  it('listens on port 3436 when PORT is unset', () => {
    const config = loadServerConfig({
      MONGODB_URI: 'mongodb://127.0.0.1:27017/square-oauth',
      SQUARE_APPLICATION_ID: 'sq0idp-test-app',
      SQUARE_APPLICATION_SECRET: 'test-application-secret-value',
      SQUARE_REDIRECT_URI: 'https://square.channchealysek.com/oauth/callback',
      ENCRYPTION_KEY: crypto.randomBytes(32).toString('base64'),
    });
    expect(config.port).toBe(3436);
  });
});
