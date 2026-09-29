import request from 'supertest';
import { beforeAll, describe, expect, it } from 'vitest';
import { evaluatePayment } from '../src/domain/paymentVerification.js';
import { SquareRequestError } from '../src/square/client.js';
import { authHeader, connectTestSeller, createTestContext, type TestContext } from './helpers.js';

describe('payment verification', () => {
  const payment = {
    id: 'PAY123',
    status: 'COMPLETED',
    amount: 1250,
    currency: 'USD',
    locationId: 'L1',
    referenceId: 'attempt-1',
  };

  it('accepts only a completed payment that matches amount, currency, location, and reference', () => {
    expect(evaluatePayment({
      requestedPaymentId: 'PAY123',
      payment,
      expectedAmount: 1250,
      expectedCurrency: 'USD',
      expectedLocationId: 'L1',
      referenceId: 'attempt-1',
    }).verified).toBe(true);

    expect(evaluatePayment({
      requestedPaymentId: 'PAY123',
      payment: null,
      expectedAmount: 1250,
      expectedCurrency: 'USD',
      expectedLocationId: 'L1',
    }).reason).toBe('payment_not_found');

    expect(evaluatePayment({
      requestedPaymentId: 'PAY123',
      payment: { ...payment, status: 'APPROVED' },
      expectedAmount: 1250,
      expectedCurrency: 'USD',
      expectedLocationId: 'L1',
    }).reason).toBe('status_not_completed');

    expect(evaluatePayment({
      requestedPaymentId: 'PAY123',
      payment,
      expectedAmount: 100,
      expectedCurrency: 'USD',
      expectedLocationId: 'L1',
    }).reason).toBe('amount_mismatch');

    expect(evaluatePayment({
      requestedPaymentId: 'PAY123',
      payment,
      expectedAmount: 1250,
      expectedCurrency: 'CAD',
      expectedLocationId: 'L1',
    }).reason).toBe('currency_mismatch');

    expect(evaluatePayment({
      requestedPaymentId: 'PAY123',
      payment,
      expectedAmount: 1250,
      expectedCurrency: 'USD',
      expectedLocationId: 'L9',
    }).reason).toBe('location_mismatch');

    expect(evaluatePayment({
      requestedPaymentId: 'PAY123',
      payment,
      expectedAmount: 1250,
      expectedCurrency: 'USD',
      expectedLocationId: 'L1',
      referenceId: 'other',
    }).reason).toBe('reference_mismatch');
  });
});

describe('seller server-to-server routes', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext();
    await connectTestSeller(ctx);
    ctx.square.payment = {
      id: 'PAY123',
      status: 'COMPLETED',
      amount: 1250,
      currency: 'USD',
      locationId: 'L1',
      referenceId: 'attempt-1',
    };
  });

  it('verifies an existing payment and ignores a client paid flag', async () => {
    const rejected = await request(ctx.app)
      .post('/api/tenants/max-donuts/payments/verify')
      .set(authHeader(ctx.secret))
      .send({
        paymentId: 'PAY123',
        expectedAmount: 1250,
        expectedCurrency: 'USD',
        paid: true,
      });
    expect(rejected.status).toBe(400);
    expect(ctx.square.calls).not.toContain('getPayment');

    const verified = await request(ctx.app)
      .post('/api/tenants/max-donuts/payments/verify')
      .set(authHeader(ctx.secret))
      .send({
        paymentId: 'PAY123',
        expectedAmount: 1250,
        expectedCurrency: 'USD',
        checkoutAttemptId: 'attempt-1',
      });
    expect(verified.status).toBe(200);
    expect(verified.body.verified).toBe(true);
    expect(verified.body.reason).toBe('verified');
    expect(verified.body.accessToken).toBeUndefined();
    expect(ctx.square.calls).toEqual(['getPayment']);

    const invalid = await request(ctx.app)
      .post('/api/tenants/max-donuts/payments/verify')
      .set(authHeader(ctx.secret))
      .send({ expectedAmount: '12.50', expectedCurrency: 'usd' });
    expect(invalid.status).toBe(400);
    expect(invalid.body.error).toBe('validation_error');
    expect(ctx.square.calls).toEqual(['getPayment']);
  });

  it('rejects card data', async () => {
    const response = await request(ctx.app)
      .post('/api/tenants/max-donuts/payments/verify')
      .set(authHeader(ctx.secret))
      .send({
        paymentId: 'PAY123',
        expectedAmount: 1250,
        expectedCurrency: 'USD',
        cvv: '123',
      });
    expect(response.status).toBe(400);
    expect(response.body.error).toBe('card_data_rejected');
  });

  it('returns mobile authorization material without a refresh token', async () => {
    const response = await request(ctx.app)
      .post('/api/tenants/max-donuts/mobile-payments/authorization')
      .set(authHeader(ctx.secret))
      .send({});
    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      available: true,
      applicationId: 'sq0idp-test-app',
      locationId: 'L1',
      accessToken: 'EAAAtestAccesstokenValue123456',
      environment: 'production',
    });
    expect(response.body.refreshToken).toBeUndefined();
    expect(JSON.stringify(response.body)).not.toContain('test-application-secret-value');
    expect(JSON.stringify(response.body)).not.toContain(ctx.square.tokens.refreshToken);
  });

  it('revokes the seller authorization and keeps the tenant', async () => {
    const response = await request(ctx.app)
      .post('/api/tenants/max-donuts/square/disconnect')
      .set(authHeader(ctx.secret))
      .send({});
    expect(response.status).toBe(200);
    expect(response.body.disconnected).toBe(true);
    expect(ctx.square.calls).toContain('revokeMerchant');
    const stored = await ctx.authorizations.findByTenantId('max-donuts');
    expect(stored?.authorizationStatus).toBe('disconnected');
    expect(stored?.accessToken).toBeNull();
    expect(stored?.refreshToken).toBeNull();
    const tenant = await ctx.tenants.findById('max-donuts');
    expect(tenant?.tenantId).toBe('max-donuts');
  });

  it('leaves stored credentials in place when Square revoke is unavailable', async () => {
    await connectTestSeller(ctx);
    ctx.square.revokeError = new SquareRequestError(503, ['SERVICE_UNAVAILABLE']);
    const response = await request(ctx.app)
      .post('/api/tenants/max-donuts/square/disconnect')
      .set(authHeader(ctx.secret))
      .send({});
    expect(response.status).toBe(502);
    const stored = await ctx.authorizations.findByTenantId('max-donuts');
    expect(stored?.authorizationStatus).toBe('connected');
    expect(stored?.accessToken).not.toBeNull();
  });
});
