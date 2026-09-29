import { encryptString } from '../crypto/encryption.js';
import { generateOAuthState, hashOAuthState, isOAuthStateShape } from '../crypto/secrets.js';
import { DuplicateMerchantError } from '../domain/errors.js';
import { renderResultPage } from '../domain/html.js';
import { selectActiveLocation, type LocationChoice } from '../domain/locations.js';
import { SQUARE_OAUTH_SCOPES } from '../domain/squarePolicy.js';
import { buildAuthorizationUrl, buildReturnUrl } from '../domain/urls.js';
import { logger } from '../logger.js';
import type { AuthorizationRepository, OAuthStateRepository, TenantRepository } from '../repositories/types.js';
import { SquareRequestError, type SquareApi } from '../square/client.js';

export interface OAuthFlowDependencies {
  applicationId: string;
  redirectUri: string;
  encryptionKey: Buffer;
  oauthStateTtlMs: number;
  tenants: TenantRepository;
  states: OAuthStateRepository;
  authorizations: AuthorizationRepository;
  square: SquareApi;
  now: () => Date;
}

export async function startOAuth(
  deps: OAuthFlowDependencies,
  input: { tenantId: string; baseUrl: string; returnPath: string },
): Promise<{ authorizationUrl: string; expiresAt: string }> {
  const state = generateOAuthState();
  const created = await deps.states.create({
    stateHash: hashOAuthState(state),
    tenantId: input.tenantId,
    returnPath: input.returnPath,
    now: deps.now(),
    ttlMs: deps.oauthStateTtlMs,
  });
  return {
    authorizationUrl: buildAuthorizationUrl({
      applicationId: deps.applicationId,
      redirectUri: deps.redirectUri,
      state,
    }),
    expiresAt: created.expiresAt.toISOString(),
  };
}

export async function handleOAuthCallback(
  deps: OAuthFlowDependencies,
  query: { state?: string; code?: string; error?: string },
): Promise<{ status: number; html: string }> {
  if (query.error) {
    if (query.state && isOAuthStateShape(query.state)) {
      await deps.states.consume(hashOAuthState(query.state), deps.now());
    }
    logger.info({ squareError: safeSquareError(query.error) }, 'seller denied or square returned an error');
    return html(400, {
      ok: false,
      title: 'Square authorization was not completed',
      message:
        query.error === 'access_denied'
          ? 'The Square account did not grant access.'
          : 'Square could not authorize this connection.',
    });
  }
  if (!query.state || !query.code) {
    return html(400, {
      ok: false,
      title: 'Square authorization was not completed',
      message: 'This connection request is missing required information.',
    });
  }
  if (!isOAuthStateShape(query.state)) {
    return html(400, {
      ok: false,
      title: 'Square authorization was not completed',
      message: 'This connection request is not valid.',
    });
  }
  const consumed = await deps.states.consume(hashOAuthState(query.state), deps.now());
  if (!consumed.ok) {
    return html(400, {
      ok: false,
      title: 'Square authorization was not completed',
      message: messageForState(consumed.reason),
    });
  }
  const tenant = await deps.tenants.findById(consumed.tenantId);
  if (!tenant) {
    return html(400, {
      ok: false,
      title: 'Square authorization was not completed',
      message: 'This store registration is no longer available.',
    });
  }
  let tokens;
  try {
    tokens = await deps.square.exchangeAuthorizationCode(query.code);
  } catch (error) {
    logger.warn(
      { tenantId: tenant.tenantId, square: squareFailure(error) },
      'authorization code exchange failed',
    );
    return html(502, {
      ok: false,
      title: 'Square authorization was not completed',
      message: 'Square did not complete the connection. Return to your store and try again.',
      returnUrl: safeReturn(tenant.baseUrl, consumed.returnPath),
    });
  }
  if (!tokens.refreshToken) {
    return html(502, {
      ok: false,
      title: 'Square authorization was not completed',
      message: 'Square did not complete the connection. Return to your store and try again.',
      returnUrl: safeReturn(tenant.baseUrl, consumed.returnPath),
    });
  }
  const now = deps.now();
  try {
    await deps.authorizations.saveConnected({
      tenantId: tenant.tenantId,
      merchantId: tokens.merchantId,
      environment: 'production',
      authorizationStatus: 'connected',
      accessToken: encryptString(tokens.accessToken, deps.encryptionKey, tenant.tenantId),
      refreshToken: encryptString(tokens.refreshToken, deps.encryptionKey, tenant.tenantId),
      accessTokenExpiresAt: tokens.expiresAt,
      accessTokenRefreshedAt: now,
      requestedScopes: [...SQUARE_OAUTH_SCOPES],
      locations: [],
      selectedLocationId: null,
      connectedAt: now,
      disconnectedAt: null,
      refreshLockUntil: null,
      refreshLockId: null,
    });
  } catch (error) {
    if (error instanceof DuplicateMerchantError) {
      await deps.square.revokeSingleAccessToken(tokens.accessToken).catch(() => undefined);
      logger.warn({ tenantId: tenant.tenantId }, 'square merchant already connected to another store');
      return html(409, {
        ok: false,
        title: 'Square account already connected',
        message: 'This Square account is already connected to another store.',
        returnUrl: safeReturn(tenant.baseUrl, consumed.returnPath),
      });
    }
    logger.error({ tenantId: tenant.tenantId }, 'seller authorization could not be stored');
    return html(500, {
      ok: false,
      title: 'Square authorization was not completed',
      message: 'The connection could not be saved. Return to your store and try again.',
      returnUrl: safeReturn(tenant.baseUrl, consumed.returnPath),
    });
  }
  let locationName: string | undefined;
  try {
    const listed = await deps.square.listLocations(tokens.accessToken);
    const locations = listed.map(toStoredLocation);
    const selected = selectActiveLocation(locations);
    await deps.authorizations.saveLocations(tenant.tenantId, locations, selected?.locationId ?? null);
    locationName = selected?.name;
  } catch (error) {
    logger.warn({ tenantId: tenant.tenantId, square: squareFailure(error) }, 'location lookup failed after connect');
  }
  return html(200, {
    ok: true,
    title: 'Square account connected',
    message: 'This store can now use the authorized Square seller account.',
    detail: locationName
      ? `Location selected: ${locationName}`
      : 'No active Square location was found yet. Choose a location from the store admin after one is active.',
    returnUrl: safeReturn(tenant.baseUrl, consumed.returnPath),
  });
}

function toStoredLocation(location: { id: string; name: string; status: string; currency: string | null }): LocationChoice {
  return {
    locationId: location.id,
    name: location.name,
    status: location.status,
    currency: location.currency,
  };
}

function messageForState(reason: 'unknown' | 'expired' | 'consumed'): string {
  if (reason === 'expired') {
    return 'This connection request has expired. Start again from your store admin.';
  }
  if (reason === 'consumed') {
    return 'This connection request was already used. Start again from your store admin.';
  }
  return 'This connection request is not valid.';
}

function safeReturn(baseUrl: string, returnPath: string): string | undefined {
  try {
    return buildReturnUrl(baseUrl, returnPath);
  } catch {
    return undefined;
  }
}

function html(
  status: number,
  input: { ok: boolean; title: string; message: string; detail?: string; returnUrl?: string },
): { status: number; html: string } {
  return { status, html: renderResultPage(input) };
}

function safeSquareError(error: string): string {
  return /^[a-z0-9_]{1,64}$/i.test(error) ? error : 'unrecognized';
}

function squareFailure(error: unknown): { status?: number; codes?: string[] } {
  if (error instanceof SquareRequestError) {
    return { status: error.status, codes: error.codes };
  }
  return {};
}
