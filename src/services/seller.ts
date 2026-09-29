import { HttpError } from '../domain/errors.js';
import type { LocationChoice } from '../domain/locations.js';
import { selectActiveLocation } from '../domain/locations.js';
import { evaluatePayment, type PaymentVerification } from '../domain/paymentVerification.js';
import { logger } from '../logger.js';
import type { AuthorizationRecord, AuthorizationRepository } from '../repositories/types.js';
import { SquareRequestError } from '../square/client.js';
import { getSellerAccess, requireSelectedLocation, type CredentialDependencies } from './credentials.js';

export interface SellerDependencies extends CredentialDependencies {
  applicationId: string;
}

export interface PublicSquareStatus {
  connected: boolean;
  merchantId: string | null;
  locationId: string | null;
  environment: 'production';
  authorizationStatus: 'connected' | 'disconnected' | 'revoked';
  expiresAt: string | null;
  scopes: string[];
  locations: Array<LocationChoice & { selected: boolean }>;
}

export async function getPublicStatus(
  authorizations: AuthorizationRepository,
  tenantId: string,
): Promise<PublicSquareStatus> {
  const record = await authorizations.findByTenantId(tenantId);
  return toPublicStatus(record);
}

export async function mobilePaymentsAuthorization(
  deps: SellerDependencies,
  tenantId: string,
): Promise<{
  available: true;
  applicationId: string;
  locationId: string;
  accessToken: string;
  environment: 'production';
}> {
  const access = requireSelectedLocation(await usingSeller(deps, tenantId, async (seller) => seller));
  return {
    available: true,
    applicationId: deps.applicationId,
    locationId: access.locationId,
    accessToken: access.accessToken,
    environment: 'production',
  };
}

export async function verifyExistingPayment(
  deps: SellerDependencies,
  tenantId: string,
  input: {
    paymentId: string;
    expectedAmount: number;
    expectedCurrency: string;
    referenceId?: string;
  },
): Promise<PaymentVerification> {
  return usingSeller(deps, tenantId, async (access) => {
    const located = requireSelectedLocation(access);
    let payment;
    try {
      payment = await deps.square.getPayment(located.accessToken, input.paymentId);
    } catch (error) {
      throw mapSquare(error, tenantId);
    }
    return evaluatePayment({
      requestedPaymentId: input.paymentId,
      payment,
      expectedAmount: input.expectedAmount,
      expectedCurrency: input.expectedCurrency,
      expectedLocationId: located.locationId,
      ...(input.referenceId !== undefined ? { referenceId: input.referenceId } : {}),
    });
  });
}

export async function disconnectSquare(deps: SellerDependencies, tenantId: string): Promise<{ disconnected: true }> {
  const record = await deps.authorizations.findByTenantId(tenantId);
  if (record?.authorizationStatus === 'connected' && record.merchantId) {
    try {
      await deps.square.revokeMerchant(record.merchantId);
    } catch (error) {
      if (!(error instanceof SquareRequestError) || !(error.authorizationEnded || error.status === 404)) {
        logger.warn({ tenantId, square: error instanceof SquareRequestError ? error.codes : [] }, 'square revoke failed');
        throw new HttpError(
          502,
          'square_unavailable',
          'Square could not revoke the authorization. The stored connection was left unchanged.',
        );
      }
    }
  }
  await deps.authorizations.clearAuthorization(tenantId, deps.now());
  return { disconnected: true };
}

export async function updateLocation(
  deps: SellerDependencies,
  tenantId: string,
  locationId: string | undefined,
): Promise<PublicSquareStatus> {
  return usingSeller(deps, tenantId, async (access) => {
    let listed;
    try {
      listed = await deps.square.listLocations(access.accessToken);
    } catch (error) {
      throw mapSquare(error, tenantId);
    }
    const locations: LocationChoice[] = listed.map((location) => ({
      locationId: location.id,
      name: location.name,
      status: location.status,
      currency: location.currency,
    }));
    let selected = locationId ?? null;
    if (selected) {
      const match = locations.find((location) => location.locationId === selected);
      if (!match || match.status !== 'ACTIVE') {
        throw new HttpError(400, 'location_unavailable', 'That Square location is not active for this seller.');
      }
    } else {
      const current = await deps.authorizations.findByTenantId(tenantId);
      const stillActive = locations.find(
        (location) => location.locationId === current?.selectedLocationId && location.status === 'ACTIVE',
      );
      selected = stillActive?.locationId ?? selectActiveLocation(locations)?.locationId ?? null;
    }
    await deps.authorizations.saveLocations(tenantId, locations, selected);
    const updated = await deps.authorizations.findByTenantId(tenantId);
    return toPublicStatus(updated);
  });
}

async function usingSeller<T>(
  deps: SellerDependencies,
  tenantId: string,
  fn: (access: Awaited<ReturnType<typeof getSellerAccess>>) => Promise<T>,
): Promise<T> {
  try {
    const access = await getSellerAccess(deps, tenantId);
    return await fn(access);
  } catch (error) {
    if (error instanceof SquareRequestError && error.authorizationEnded) {
      await deps.authorizations.markRevoked(tenantId, deps.now());
      throw new HttpError(
        409,
        'authorization_revoked',
        'Square authorization expired or was revoked. Connect the Square account again.',
      );
    }
    if (error instanceof SquareRequestError) {
      throw new HttpError(502, 'square_unavailable', 'Square could not complete the request.');
    }
    throw error;
  }
}

function mapSquare(error: unknown, tenantId: string): Error {
  if (error instanceof SquareRequestError && error.authorizationEnded) {
    return error;
  }
  if (error instanceof SquareRequestError) {
    logger.warn({ tenantId, codes: error.codes, status: error.status }, 'square seller request failed');
    return new HttpError(502, 'square_unavailable', 'Square could not complete the request.');
  }
  return error instanceof Error ? error : new Error('square request failed');
}

function toPublicStatus(record: AuthorizationRecord | null): PublicSquareStatus {
  const connected = Boolean(
    record &&
      record.authorizationStatus === 'connected' &&
      record.merchantId &&
      record.accessToken &&
      record.refreshToken,
  );
  return {
    connected,
    merchantId: connected ? record!.merchantId : null,
    locationId: connected ? record!.selectedLocationId : null,
    environment: 'production',
    authorizationStatus: record?.authorizationStatus ?? 'disconnected',
    expiresAt: connected && record?.accessTokenExpiresAt ? record.accessTokenExpiresAt.toISOString() : null,
    scopes: connected ? record!.requestedScopes : [],
    locations: connected
      ? record!.locations.map((location) => ({
          ...location,
          selected: location.locationId === record!.selectedLocationId,
        }))
      : [],
  };
}
