import { SQUARE_API_VERSION, SQUARE_PRODUCTION_ORIGIN } from '../domain/squarePolicy.js';
import type { SquarePaymentFacts } from '../domain/paymentVerification.js';

export interface ObtainedTokens {
  accessToken: string;
  refreshToken: string | null;
  expiresAt: Date;
  merchantId: string;
}

export interface SquareLocationResult {
  id: string;
  name: string;
  status: string;
  currency: string | null;
}

export interface SquareApi {
  exchangeAuthorizationCode(code: string): Promise<ObtainedTokens>;
  refreshAccessToken(refreshToken: string): Promise<ObtainedTokens>;
  revokeMerchant(merchantId: string): Promise<void>;
  revokeSingleAccessToken(accessToken: string): Promise<void>;
  listLocations(accessToken: string): Promise<SquareLocationResult[]>;
  getPayment(accessToken: string, paymentId: string): Promise<SquarePaymentFacts | null>;
}

export class SquareRequestError extends Error {
  readonly authorizationEnded: boolean;

  constructor(
    readonly status: number,
    readonly codes: string[],
    authorizationEnded = false,
  ) {
    super('Square request failed');
    this.name = 'SquareRequestError';
    this.authorizationEnded =
      authorizationEnded ||
      status === 401 ||
      codes.includes('service.not_authorized') ||
      codes.includes('ACCESS_TOKEN_REVOKED') ||
      codes.includes('ACCESS_TOKEN_EXPIRED');
  }
}

export class SquareHttpClient implements SquareApi {
  constructor(
    private readonly applicationId: string,
    private readonly applicationSecret: string,
    private readonly redirectUri: string,
    private readonly origin = SQUARE_PRODUCTION_ORIGIN,
  ) {}

  async exchangeAuthorizationCode(code: string): Promise<ObtainedTokens> {
    const tokens = await this.obtainToken({
      client_id: this.applicationId,
      client_secret: this.applicationSecret,
      code,
      grant_type: 'authorization_code',
      redirect_uri: this.redirectUri,
      use_jwt: true,
    }, false);
    if (!tokens.refreshToken) {
      await this.revokeSingleAccessToken(tokens.accessToken).catch(() => undefined);
      throw new SquareRequestError(200, ['MISSING_REFRESH_TOKEN']);
    }
    return tokens;
  }

  async refreshAccessToken(refreshToken: string): Promise<ObtainedTokens> {
    return this.obtainToken({
      client_id: this.applicationId,
      client_secret: this.applicationSecret,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      redirect_uri: this.redirectUri,
      use_jwt: true,
    }, true);
  }

  async revokeMerchant(merchantId: string): Promise<void> {
    await this.revoke({
      client_id: this.applicationId,
      merchant_id: merchantId,
      revoke_only_access_token: false,
    });
  }

  async revokeSingleAccessToken(accessToken: string): Promise<void> {
    await this.revoke({
      client_id: this.applicationId,
      access_token: accessToken,
      revoke_only_access_token: true,
    });
  }

  async listLocations(accessToken: string): Promise<SquareLocationResult[]> {
    const response = await this.request('/v2/locations', { method: 'GET', accessToken });
    if (response.status === 401) {
      throw endedError(response.status, response.codes);
    }
    if (response.status !== 200) {
      throw new SquareRequestError(response.status, response.codes);
    }
    const locations = readLocations(response.body);
    return locations;
  }

  async getPayment(accessToken: string, paymentId: string): Promise<SquarePaymentFacts | null> {
    const response = await this.request(`/v2/payments/${encodeURIComponent(paymentId)}`, {
      method: 'GET',
      accessToken,
    });
    if (response.status === 404) {
      return null;
    }
    if (response.status === 401) {
      throw endedError(response.status, response.codes);
    }
    if (response.status !== 200) {
      throw new SquareRequestError(response.status, response.codes);
    }
    return readPayment(response.body);
  }

  private async obtainToken(body: Record<string, unknown>, refresh: boolean): Promise<ObtainedTokens> {
    const response = await this.request('/oauth2/token', { method: 'POST', body });
    if (response.status !== 200) {
      throw new SquareRequestError(response.status, response.codes, refresh && (response.status === 400 || response.status === 401));
    }
    return readTokens(response.body);
  }

  private async revoke(body: Record<string, unknown>): Promise<void> {
    const response = await this.request('/oauth2/revoke', {
      method: 'POST',
      body,
      clientAuthorization: true,
    });
    if (response.status === 404 || response.status === 401) {
      throw endedError(response.status, response.codes);
    }
    if (response.status !== 200) {
      throw new SquareRequestError(response.status, response.codes);
    }
  }

  private async request(
    path: string,
    input: {
      method: 'GET' | 'POST';
      body?: Record<string, unknown>;
      accessToken?: string;
      clientAuthorization?: boolean;
    },
  ): Promise<{ status: number; codes: string[]; body: unknown }> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'Square-Version': SQUARE_API_VERSION,
      'User-Agent': 'square-oauth-broker',
    };
    if (input.body) {
      headers['Content-Type'] = 'application/json';
    }
    if (input.accessToken) {
      headers.Authorization = `Bearer ${input.accessToken}`;
    }
    if (input.clientAuthorization) {
      headers.Authorization = `Client ${this.applicationSecret}`;
    }
    let response: Response;
    try {
      response = await fetch(new URL(path, this.origin), {
        method: input.method,
        headers,
        body: input.body ? JSON.stringify(input.body) : undefined,
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new SquareRequestError(0, ['NETWORK']);
    }
    const text = await response.text();
    if (text.length > 1_000_000) {
      throw new SquareRequestError(response.status, ['RESPONSE_TOO_LARGE']);
    }
    let body: unknown = null;
    if (text.length > 0) {
      try {
        body = JSON.parse(text) as unknown;
      } catch {
        throw new SquareRequestError(response.status, ['INVALID_JSON']);
      }
    }
    return { status: response.status, codes: readErrorCodes(body), body };
  }
}

function endedError(status: number, codes: string[]): SquareRequestError {
  return new SquareRequestError(status, codes, true);
}

function readErrorCodes(body: unknown): string[] {
  if (!body || typeof body !== 'object') {
    return [];
  }
  const record = body as Record<string, unknown>;
  const codes: string[] = [];
  if (typeof record.type === 'string') {
    codes.push(record.type);
  }
  if (Array.isArray(record.errors)) {
    for (const item of record.errors) {
      if (item && typeof item === 'object' && typeof (item as { code?: unknown }).code === 'string') {
        codes.push((item as { code: string }).code);
      }
    }
  }
  return codes.slice(0, 5);
}

function readTokens(body: unknown): ObtainedTokens {
  if (!body || typeof body !== 'object') {
    throw new SquareRequestError(200, ['INVALID_TOKEN_RESPONSE']);
  }
  const record = body as Record<string, unknown>;
  const accessToken = record.access_token;
  const merchantId = record.merchant_id;
  const expiresAtRaw = record.expires_at;
  const refreshToken = record.refresh_token;
  if (typeof accessToken !== 'string' || accessToken.length < 8) {
    throw new SquareRequestError(200, ['INVALID_TOKEN_RESPONSE']);
  }
  if (typeof merchantId !== 'string' || merchantId.length < 1 || merchantId.length > 191) {
    throw new SquareRequestError(200, ['INVALID_TOKEN_RESPONSE']);
  }
  if (typeof expiresAtRaw !== 'string') {
    throw new SquareRequestError(200, ['INVALID_TOKEN_RESPONSE']);
  }
  const expiresAt = new Date(expiresAtRaw);
  if (Number.isNaN(expiresAt.getTime())) {
    throw new SquareRequestError(200, ['INVALID_TOKEN_RESPONSE']);
  }
  if (refreshToken !== undefined && refreshToken !== null && typeof refreshToken !== 'string') {
    throw new SquareRequestError(200, ['INVALID_TOKEN_RESPONSE']);
  }
  return {
    accessToken,
    refreshToken: typeof refreshToken === 'string' && refreshToken.length > 0 ? refreshToken : null,
    expiresAt,
    merchantId,
  };
}

function readLocations(body: unknown): SquareLocationResult[] {
  if (!body || typeof body !== 'object') {
    return [];
  }
  const locations = (body as { locations?: unknown }).locations;
  if (!Array.isArray(locations)) {
    return [];
  }
  const results: SquareLocationResult[] = [];
  for (const item of locations) {
    if (!item || typeof item !== 'object') {
      continue;
    }
    const record = item as Record<string, unknown>;
    if (typeof record.id !== 'string' || !/^[A-Za-z0-9]+$/.test(record.id)) {
      continue;
    }
    const name = typeof record.name === 'string' && record.name.trim().length > 0
      ? record.name.trim().slice(0, 200)
      : record.id;
    const status = typeof record.status === 'string' ? record.status : 'INACTIVE';
    const currency = typeof record.currency === 'string' ? record.currency : null;
    results.push({ id: record.id, name, status, currency });
  }
  return results;
}

function readPayment(body: unknown): SquarePaymentFacts {
  if (!body || typeof body !== 'object' || !('payment' in body)) {
    throw new SquareRequestError(200, ['INVALID_PAYMENT_RESPONSE']);
  }
  const payment = (body as { payment?: unknown }).payment;
  if (!payment || typeof payment !== 'object') {
    throw new SquareRequestError(200, ['INVALID_PAYMENT_RESPONSE']);
  }
  const record = payment as Record<string, unknown>;
  if (typeof record.id !== 'string') {
    throw new SquareRequestError(200, ['INVALID_PAYMENT_RESPONSE']);
  }
  const money = record.amount_money;
  let amount: number | null = null;
  let currency: string | null = null;
  if (money && typeof money === 'object') {
    const amountMoney = money as Record<string, unknown>;
    if (typeof amountMoney.amount === 'number' && Number.isInteger(amountMoney.amount)) {
      amount = amountMoney.amount;
    }
    if (typeof amountMoney.currency === 'string') {
      currency = amountMoney.currency;
    }
  }
  return {
    id: record.id,
    status: typeof record.status === 'string' ? record.status : null,
    amount,
    currency,
    locationId: typeof record.location_id === 'string' ? record.location_id : null,
    referenceId: typeof record.reference_id === 'string' ? record.reference_id : null,
  };
}
