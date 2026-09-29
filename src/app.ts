import express, { type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { ZodError } from 'zod';
import type { AppConfig } from './config.js';
import { CALLBACK_SCRIPT_HASH, renderResultPage } from './domain/html.js';
import { HttpError } from './domain/errors.js';
import { logger } from './logger.js';
import type { AuthorizationRepository, OAuthStateRepository, TenantRepository } from './repositories/types.js';
import type { SquareApi } from './square/client.js';
import { handleOAuthCallback, startOAuth } from './services/oauthFlow.js';
import {
  disconnectSquare,
  getPublicStatus,
  mobilePaymentsAuthorization,
  updateLocation,
  verifyExistingPayment,
} from './services/seller.js';
import {
  asyncHandler,
  parseCallbackQuery,
  parseLocationBody,
  parseStartBody,
  parseVerifyBody,
  rejectCardData,
  requireTenant,
} from './http/http.js';

export interface AppDependencies {
  config: AppConfig;
  tenants: TenantRepository;
  states: OAuthStateRepository;
  authorizations: AuthorizationRepository;
  square: SquareApi;
  now?: () => Date;
  isDatabaseHealthy?: () => boolean;
}

export function createApp(deps: AppDependencies): express.Express {
  const now = deps.now ?? (() => new Date());
  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);
  // One reverse proxy (Nginx Proxy Manager). Do not publish port 3436 on the public internet.
  app.set('trust proxy', 1);
  app.use(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'none'"],
        frameAncestors: ["'none'"],
        scriptSrc: [`'sha256-${CALLBACK_SCRIPT_HASH}'`],
        styleSrc: ["'unsafe-inline'"],
      },
    },
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginEmbedderPolicy: false,
  }));
  app.use(express.json({ limit: '16kb', strict: true }));

  const oauthDeps = {
    applicationId: deps.config.applicationId,
    redirectUri: deps.config.redirectUri,
    encryptionKey: deps.config.encryptionKey,
    oauthStateTtlMs: deps.config.oauthStateTtlMs,
    tenants: deps.tenants,
    states: deps.states,
    authorizations: deps.authorizations,
    square: deps.square,
    now,
  };
  const sellerDeps = {
    applicationId: deps.config.applicationId,
    encryptionKey: deps.config.encryptionKey,
    authorizations: deps.authorizations,
    square: deps.square,
    now,
  };

  app.get('/health', (_req, res) => {
    const ok = deps.isDatabaseHealthy?.() ?? true;
    res.status(ok ? 200 : 503).json({ ok, service: 'square-oauth' });
  });

  const startLimiter = limiter(deps.config.rateLimits.startPerMinute);
  const callbackLimiter = limiter(deps.config.rateLimits.callbackPerMinute);
  const apiLimiter = limiter(deps.config.rateLimits.apiPerMinute);

  app.post(
    '/api/tenants/:tenantId/oauth/start',
    startLimiter,
    rejectCardData,
    requireTenant(deps.tenants, 'param'),
    asyncHandler(async (req, res) => {
      const body = parseStartBody(req.body);
      if (!req.tenant || req.tenant.tenantId !== req.params.tenantId) {
        res.status(401).json({ error: 'unauthorized', message: 'Tenant authentication failed' });
        return;
      }
      const started = await startOAuth(oauthDeps, {
        tenantId: req.tenant.tenantId,
        baseUrl: req.tenant.baseUrl,
        returnPath: body.returnPath,
      });
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).json(started);
    }),
  );

  app.get(
    '/oauth/callback',
    callbackLimiter,
    rejectCardData,
    asyncHandler(async (req, res) => {
      const query = parseCallbackQuery(req.query);
      const result = await handleOAuthCallback(oauthDeps, query);
      sendHtml(res, result.status, result.html);
    }),
  );

  const tenantParam = '/api/tenants/:tenantId';
  app.get(
    `${tenantParam}/square/status`,
    apiLimiter,
    requireTenant(deps.tenants, 'param'),
    asyncHandler(async (req, res) => {
      const status = await getPublicStatus(deps.authorizations, req.tenant!.tenantId);
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).json(status);
    }),
  );

  app.put(
    `${tenantParam}/square/location`,
    apiLimiter,
    rejectCardData,
    requireTenant(deps.tenants, 'param'),
    asyncHandler(async (req, res) => {
      const body = parseLocationBody(req.body);
      const status = await updateLocation(sellerDeps, req.tenant!.tenantId, body.locationId);
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).json(status);
    }),
  );

  app.post(
    `${tenantParam}/square/disconnect`,
    apiLimiter,
    rejectCardData,
    requireTenant(deps.tenants, 'param'),
    asyncHandler(async (req, res) => {
      const result = await disconnectSquare(sellerDeps, req.tenant!.tenantId);
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).json({ ...result, authorizationStatus: 'disconnected' });
    }),
  );

  app.post(
    `${tenantParam}/mobile-payments/authorization`,
    apiLimiter,
    rejectCardData,
    requireTenant(deps.tenants, 'param'),
    asyncHandler(async (req, res) => {
      const result = await mobilePaymentsAuthorization(sellerDeps, req.tenant!.tenantId);
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).json(result);
    }),
  );

  app.post(
    `${tenantParam}/payments/verify`,
    apiLimiter,
    rejectCardData,
    requireTenant(deps.tenants, 'param'),
    asyncHandler(async (req, res) => {
      const body = parseVerifyBody(req.body);
      const result = await verifyExistingPayment(sellerDeps, req.tenant!.tenantId, body);
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).json(result);
    }),
  );

  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found', message: 'Not found' });
  });

  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) {
      next(err);
      return;
    }
    if (err instanceof ZodError) {
      if (req.path === '/oauth/callback') {
        sendHtml(res, 400, renderResultPage({
          ok: false,
          title: 'Square authorization was not completed',
          message: 'This connection request is not valid.',
        }));
        return;
      }
      res.status(400).json({
        error: 'validation_error',
        message: 'Request validation failed',
        fields: err.issues.map((issue) => issue.path.join('.')),
      });
      return;
    }
    if (err instanceof HttpError) {
      if (req.path === '/oauth/callback') {
        sendHtml(res, err.status, renderResultPage({
          ok: false,
          title: 'Square authorization was not completed',
          message: err.message,
        }));
        return;
      }
      res.status(err.status).json({ error: err.code, message: err.message });
      return;
    }
    if (isBodySyntaxError(err)) {
      res.status(400).json({ error: 'invalid_json', message: 'Request body must be valid JSON' });
      return;
    }
    if (isPayloadTooLarge(err)) {
      res.status(413).json({ error: 'payload_too_large', message: 'Request body is too large' });
      return;
    }
    logger.error({ name: err instanceof Error ? err.name : 'error', path: req.path }, 'request failed');
    res.status(500).json({ error: 'internal_error', message: 'The request could not be completed' });
  });

  return app;
}

function limiter(limit: number): ReturnType<typeof rateLimit> {
  return rateLimit({
    windowMs: 60_000,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    statusCode: 429,
    message: { error: 'rate_limited', message: 'Too many requests' },
  });
}

function sendHtml(res: Response, status: number, html: string): void {
  res.status(status);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.send(html);
}

function isBodySyntaxError(err: unknown): boolean {
  return err instanceof SyntaxError && 'status' in err && (err as { status?: number }).status === 400;
}

function isPayloadTooLarge(err: unknown): boolean {
  return Boolean(err && typeof err === 'object' && 'status' in err && (err as { status?: number }).status === 413);
}
