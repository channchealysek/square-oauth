import { parseEncryptionKey } from './crypto/encryption.js';
import { OAUTH_STATE_TTL_MS } from './domain/squarePolicy.js';

export interface AppConfig {
  port: number;
  mongodbUri: string;
  applicationId: string;
  applicationSecret: string;
  redirectUri: string;
  encryptionKey: Buffer;
  oauthStateTtlMs: number;
  rateLimits: {
    startPerMinute: number;
    callbackPerMinute: number;
    apiPerMinute: number;
  };
}

const REQUIRED = [
  'MONGODB_URI',
  'SQUARE_APPLICATION_ID',
  'SQUARE_APPLICATION_SECRET',
  'SQUARE_REDIRECT_URI',
  'ENCRYPTION_KEY',
] as const;

export function loadServerConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const missing = REQUIRED.filter((name) => !env[name]?.trim());
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
  const applicationId = env.SQUARE_APPLICATION_ID!.trim();
  if (!/^sq0idp-[A-Za-z0-9_-]+$/.test(applicationId)) {
    throw new Error('SQUARE_APPLICATION_ID must be a production application ID starting with sq0idp-');
  }
  const applicationSecret = env.SQUARE_APPLICATION_SECRET!.trim();
  if (applicationSecret.length < 16 || /changeme|replace-me|your-secret/i.test(applicationSecret)) {
    throw new Error('SQUARE_APPLICATION_SECRET is not valid');
  }
  const redirectUri = parseRedirectUri(env.SQUARE_REDIRECT_URI!.trim(), env.NODE_ENV === 'production');
  const mongodbUri = env.MONGODB_URI!.trim();
  if (!/^mongodb(\+srv)?:\/\//.test(mongodbUri)) {
    throw new Error('MONGODB_URI must be a mongodb connection string');
  }
  return {
    port: parsePort(env.PORT),
    mongodbUri,
    applicationId,
    applicationSecret,
    redirectUri,
    encryptionKey: parseEncryptionKey(env.ENCRYPTION_KEY!),
    oauthStateTtlMs: OAUTH_STATE_TTL_MS,
    rateLimits: {
      startPerMinute: 30,
      callbackPerMinute: 60,
      apiPerMinute: 300,
    },
  };
}

export function loadMongoUri(env: NodeJS.ProcessEnv = process.env): string {
  const mongodbUri = env.MONGODB_URI?.trim() ?? '';
  if (!/^mongodb(\+srv)?:\/\//.test(mongodbUri)) {
    throw new Error('MONGODB_URI must be a mongodb connection string');
  }
  return mongodbUri;
}

function parsePort(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === '') {
    return 3436;
  }
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer from 1 to 65535');
  }
  return port;
}

function parseRedirectUri(raw: string, production: boolean): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('SQUARE_REDIRECT_URI must be an https URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error('SQUARE_REDIRECT_URI must be an https URL with path /oauth/callback');
  }
  if (url.pathname !== '/oauth/callback') {
    throw new Error('SQUARE_REDIRECT_URI path must be /oauth/callback');
  }
  if (production && (url.hostname === 'localhost' || url.hostname === '127.0.0.1')) {
    throw new Error('SQUARE_REDIRECT_URI must not target localhost in production');
  }
  return `${url.origin}${url.pathname}`;
}
