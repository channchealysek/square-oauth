import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { z } from 'zod';
import { DUMMY_TENANT_SECRET, isTenantSecretShape, verifyTenantSecret } from '../crypto/secrets.js';
import { containsCardData } from '../domain/cardData.js';
import { HttpError } from '../domain/errors.js';
import { isTenantId, normalizeReturnPath } from '../domain/urls.js';
import type { TenantRepository } from '../repositories/types.js';

export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
): RequestHandler {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
}

export function requireTenant(tenants: TenantRepository, source: 'param' | 'body'): RequestHandler {
  return asyncHandler(async (req, res, next) => {
    const presented = readBearer(req.get('authorization'));
    const tenantId = source === 'param' ? req.params.tenantId : readBodyTenantId(req.body);
    if (!presented || !isTenantSecretShape(presented) || !tenantId || !isTenantId(tenantId)) {
      await verifyTenantSecret(presented ?? '0'.repeat(43), DUMMY_TENANT_SECRET.secretSalt, DUMMY_TENANT_SECRET.secretHash);
      res.status(401).json(unauthorized());
      return;
    }
    const tenant = await tenants.findById(tenantId);
    const salt = tenant?.secretSalt ?? DUMMY_TENANT_SECRET.secretSalt;
    const hash = tenant?.secretHash ?? DUMMY_TENANT_SECRET.secretHash;
    const matches = await verifyTenantSecret(presented, salt, hash);
    if (!tenant || !matches || tenant.tenantId !== tenantId) {
      res.status(401).json(unauthorized());
      return;
    }
    if (!tenant.active) {
      res.status(403).json({ error: 'tenant_inactive', message: 'This store is disabled.' });
      return;
    }
    if (source === 'param' && req.params.tenantId !== tenant.tenantId) {
      res.status(401).json(unauthorized());
      return;
    }
    req.tenant = { tenantId: tenant.tenantId, baseUrl: tenant.baseUrl };
    next();
  });
}

export function rejectCardData(req: Request, _res: Response, next: NextFunction): void {
  if (containsCardData(req.body) || containsCardData(req.query)) {
    next(new HttpError(400, 'card_data_rejected', 'Card data is not accepted by this service.'));
    return;
  }
  next();
}

const startSchema = z
  .object({
    returnPath: z.string().optional(),
  })
  .strict();

export function parseStartBody(body: unknown): { returnPath: string } {
  const parsed = startSchema.parse(body ?? {});
  return {
    returnPath: normalizeReturnPath(parsed.returnPath),
  };
}

const verifySchema = z
  .object({
    paymentId: z.string().regex(/^[A-Za-z0-9]{1,192}$/),
    expectedAmount: z.number().int().min(0).max(1_000_000_000),
    expectedCurrency: z.string().regex(/^[A-Z]{3}$/),
    referenceId: z.string().regex(/^[A-Za-z0-9._:-]{1,40}$/).optional(),
    checkoutAttemptId: z.string().regex(/^[A-Za-z0-9._:-]{1,40}$/).optional(),
  })
  .strict();

export function parseVerifyBody(body: unknown): {
  paymentId: string;
  expectedAmount: number;
  expectedCurrency: string;
  referenceId?: string;
} {
  const parsed = verifySchema.parse(body);
  if (parsed.referenceId && parsed.checkoutAttemptId && parsed.referenceId !== parsed.checkoutAttemptId) {
    throw new HttpError(400, 'validation_error', 'referenceId and checkoutAttemptId must match when both are provided');
  }
  const referenceId = parsed.referenceId ?? parsed.checkoutAttemptId;
  return {
    paymentId: parsed.paymentId,
    expectedAmount: parsed.expectedAmount,
    expectedCurrency: parsed.expectedCurrency,
    ...(referenceId !== undefined ? { referenceId } : {}),
  };
}

const locationSchema = z
  .object({
    locationId: z.string().regex(/^[A-Za-z0-9]{1,64}$/).optional(),
  })
  .strict();

export function parseLocationBody(body: unknown): { locationId?: string } {
  const parsed = locationSchema.parse(body ?? {});
  return parsed.locationId ? { locationId: parsed.locationId } : {};
}

const callbackQuerySchema = z.object({
  state: z.string().max(256).optional(),
  code: z.string().min(8).max(4096).optional(),
  error: z.string().max(64).optional(),
  error_description: z.string().max(300).optional(),
  response_type: z.string().max(32).optional(),
});

export function parseCallbackQuery(query: Request['query']): { state?: string; code?: string; error?: string } {
  const parsed = callbackQuerySchema.parse({
    state: one(query.state),
    code: one(query.code),
    error: one(query.error),
    error_description: one(query.error_description),
    response_type: one(query.response_type),
  });
  return {
    ...(parsed.state ? { state: parsed.state } : {}),
    ...(parsed.code ? { code: parsed.code } : {}),
    ...(parsed.error ? { error: parsed.error } : {}),
  };
}

function one(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return value;
  }
  return undefined;
}

function readBearer(header: string | undefined): string | null {
  if (!header) {
    return null;
  }
  const match = /^Bearer\s+(\S+)$/.exec(header);
  return match?.[1] ?? null;
}

function readBodyTenantId(body: unknown): string | undefined {
  if (!body || typeof body !== 'object' || !('tenantId' in body)) {
    return undefined;
  }
  const tenantId = (body as { tenantId?: unknown }).tenantId;
  return typeof tenantId === 'string' ? tenantId : undefined;
}

function unauthorized(): { error: string; message: string } {
  return { error: 'unauthorized', message: 'Tenant authentication failed' };
}
