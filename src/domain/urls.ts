import { HttpError } from './errors.js';
import { SQUARE_OAUTH_SCOPES, SQUARE_PRODUCTION_ORIGIN } from './squarePolicy.js';

const TENANT_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export function isTenantId(value: string): boolean {
  return value.length >= 1 && value.length <= 64 && TENANT_ID.test(value);
}

export function normalizeBaseUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error('base URL must be a valid https URL');
  }
  if (url.protocol !== 'https:') {
    throw new Error('base URL must use https');
  }
  if (url.username || url.password) {
    throw new Error('base URL must not include credentials');
  }
  if (url.search || url.hash) {
    throw new Error('base URL must not include a query or fragment');
  }
  if (!url.hostname || url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
    throw new Error('base URL hostname is not allowed');
  }
  const path = url.pathname === '/' ? '' : url.pathname.replace(/\/$/, '');
  return `${url.origin}${path}`;
}

export function normalizeReturnPath(input: string | undefined): string {
  if (input === undefined || input === '') {
    return '/';
  }
  if (
    !input.startsWith('/') ||
    input.startsWith('//') ||
    input.includes('\\') ||
    input.includes('://') ||
    input.includes('?') ||
    input.includes('#')
  ) {
    throw new HttpError(400, 'invalid_return_path', 'returnPath must be a relative path');
  }
  if (input.length > 200) {
    throw new HttpError(400, 'invalid_return_path', 'returnPath is too long');
  }
  return input;
}

export function buildReturnUrl(baseUrl: string, returnPath: string): string {
  const base = new URL(baseUrl);
  if (base.protocol !== 'https:') {
    throw new Error('base URL must use https');
  }
  const prefix = base.pathname === '/' ? '' : base.pathname.replace(/\/$/, '');
  const combined = `${prefix}${returnPath}`.replace(/\/{2,}/g, '/');
  const url = new URL(base.origin);
  url.pathname = combined;
  if (url.origin !== base.origin) {
    throw new Error('return url origin mismatch');
  }
  return url.toString();
}

export function buildAuthorizationUrl(input: {
  applicationId: string;
  redirectUri: string;
  state: string;
}): string {
  const url = new URL('/oauth2/authorize', SQUARE_PRODUCTION_ORIGIN);
  url.searchParams.set('client_id', input.applicationId);
  url.searchParams.set('scope', SQUARE_OAUTH_SCOPES.join(' '));
  url.searchParams.set('session', 'false');
  url.searchParams.set('state', input.state);
  url.searchParams.set('redirect_uri', input.redirectUri);
  return url.toString();
}
