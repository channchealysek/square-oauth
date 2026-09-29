import request from 'supertest';
import { beforeAll, describe, expect, it } from 'vitest';
import { generateOAuthState, hashOAuthState } from '../src/crypto/secrets.js';
import { classifyOAuthState } from '../src/domain/oauthState.js';
import { OAUTH_STATE_TTL_MS, needsAccessTokenRefresh } from '../src/domain/squarePolicy.js';
import { authHeader, createTestContext, type TestContext } from './helpers.js';

describe('oauth state rules', () => {
  it('classifies unknown, expired, consumed, and valid states', () => {
    const now = new Date('2026-09-28T12:00:00.000Z');
    expect(classifyOAuthState(null, now)).toBe('unknown');
    expect(classifyOAuthState({ consumedAt: null, expiresAt: new Date('2026-09-28T11:59:00.000Z') }, now)).toBe('expired');
    expect(classifyOAuthState({ consumedAt: now, expiresAt: new Date('2026-09-28T12:10:00.000Z') }, now)).toBe('consumed');
    expect(classifyOAuthState({ consumedAt: null, expiresAt: new Date('2026-09-28T12:10:00.000Z') }, now)).toBe('valid');
  });

  it('refreshes access tokens once fewer than 23 days remain', () => {
    const now = new Date('2026-09-28T12:00:00.000Z');
    const day = 24 * 60 * 60 * 1000;
    expect(needsAccessTokenRefresh(new Date(now.getTime() + 23 * day), now)).toBe(true);
    expect(needsAccessTokenRefresh(new Date(now.getTime() + 23 * day + 1), now)).toBe(false);
    expect(needsAccessTokenRefresh(null, now)).toBe(true);
  });

  it('creates a single-use state that expires', async () => {
    const ctx = await createTestContext();
    const now = new Date();
    const state = generateOAuthState();
    const created = await ctx.states.create({
      stateHash: hashOAuthState(state),
      tenantId: 'max-donuts',
      returnPath: '/admin/square',
      now,
      ttlMs: OAUTH_STATE_TTL_MS,
    });
    expect(created.expiresAt.getTime() - now.getTime()).toBe(OAUTH_STATE_TTL_MS);
    const first = await ctx.states.consume(hashOAuthState(state), now);
    expect(first.ok).toBe(true);
    const replay = await ctx.states.consume(hashOAuthState(state), now);
    expect(replay).toEqual({ ok: false, reason: 'consumed' });
    const expiredState = generateOAuthState();
    await ctx.states.create({
      stateHash: hashOAuthState(expiredState),
      tenantId: 'max-donuts',
      returnPath: '/',
      now,
      ttlMs: -1_000,
    });
    const expired = await ctx.states.consume(hashOAuthState(expiredState), now);
    expect(expired).toEqual({ ok: false, reason: 'expired' });
    const unknown = await ctx.states.consume(hashOAuthState(generateOAuthState()), now);
    expect(unknown).toEqual({ ok: false, reason: 'unknown' });
  });
});

describe('oauth callback state validation', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
    ctx.square.locations = [
      { id: 'L2', name: 'Zulu', status: 'ACTIVE', currency: 'USD' },
      { id: 'L0', name: 'Closed', status: 'INACTIVE', currency: 'USD' },
      { id: 'L1', name: 'Alpha', status: 'ACTIVE', currency: 'USD' },
    ];
  });

  it('rejects a missing, unknown, expired, or replayed state without leaking tokens', async () => {
    const missing = await request(ctx.app).get('/oauth/callback');
    expect(missing.status).toBe(400);
    expect(missing.text).toContain('missing required information');
    expect(ctx.square.calls).not.toContain('exchange');

    const unknown = await request(ctx.app).get('/oauth/callback').query({ state: generateOAuthState(), code: 'sq0cgb-test-code' });
    expect(unknown.status).toBe(400);
    expect(unknown.text).toContain('not valid');

    const expiredState = generateOAuthState();
    await ctx.states.create({
      stateHash: hashOAuthState(expiredState),
      tenantId: 'max-donuts',
      returnPath: '/',
      now: new Date(),
      ttlMs: -1_000,
    });
    const expired = await request(ctx.app).get('/oauth/callback').query({ state: expiredState, code: 'sq0cgb-test-code' });
    expect(expired.status).toBe(400);
    expect(expired.text).toContain('has expired');
    expect(ctx.square.calls).not.toContain('exchange');

    const deniedState = generateOAuthState();
    await ctx.states.create({
      stateHash: hashOAuthState(deniedState),
      tenantId: 'max-donuts',
      returnPath: '/admin/square',
      now: new Date(),
      ttlMs: OAUTH_STATE_TTL_MS,
    });
    const denied = await request(ctx.app).get('/oauth/callback').query({
      error: 'access_denied',
      error_description: 'user_denied',
      state: deniedState,
    });
    expect(denied.status).toBe(400);
    expect(denied.text).toContain('did not grant access');
    expect(denied.text).not.toContain('user_denied');
    expect(ctx.square.calls).not.toContain('exchange');
  });

  it('consumes state before exchange and does not put tokens in the result page', async () => {
    const started = await request(ctx.app)
      .post('/api/tenants/max-donuts/oauth/start')
      .set(authHeader(ctx.secret))
      .send({ returnPath: '/admin/square' });
    const state = new URL(started.body.authorizationUrl).searchParams.get('state');
    expect(state).toBeTruthy();
    const first = await request(ctx.app).get('/oauth/callback').query({ state, code: 'sq0cgb-test-code' });
    expect(first.status).toBe(200);
    expect(first.headers['cache-control']).toContain('no-store');
    expect(first.text).toContain('Square account connected');
    expect(first.text).toContain('Alpha');
    expect(first.text).toContain('https://maxdonut.channchealysek.com/admin/square');
    expect(first.text).not.toContain('EAAAtestAccesstokenValue123456');
    expect(first.text).not.toContain('EAAAtestRefreshtokenValue123456');
    expect(first.text).not.toContain('sq0cgb-test-code');
    expect(first.text).not.toContain('test-application-secret-value');
    expect(ctx.square.calls.filter((call) => call === 'exchange')).toHaveLength(1);

    const stored = await ctx.authorizations.findByTenantId('max-donuts');
    expect(stored?.selectedLocationId).toBe('L1');
    expect(stored?.accessToken?.ciphertext).not.toContain('EAAAtestAccesstokenValue123456');
    expect(stored?.merchantId).toBe('MERCHANT1');

    const replay = await request(ctx.app).get('/oauth/callback').query({ state, code: 'sq0cgb-test-code' });
    expect(replay.status).toBe(400);
    expect(replay.text).toContain('already used');
    expect(ctx.square.calls.filter((call) => call === 'exchange')).toHaveLength(1);
  });
});
