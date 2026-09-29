import pino from 'pino';

const SECRET_KEYS = new Set([
  'authorization',
  'accesstoken',
  'refreshtoken',
  'clientsecret',
  'applicationsecret',
  'tenantsecret',
  'encryptionkey',
  'secrethash',
  'secretsalt',
  'secret',
  'password',
  'pan',
  'cvv',
  'cvc',
  'cardnumber',
  'track1',
  'track2',
  'oauthcode',
  'authorizationcode',
]);

export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  redact: {
    paths: [
      'req.headers.authorization',
      'authorization',
      'accessToken',
      'access_token',
      'refreshToken',
      'refresh_token',
      'client_secret',
      'clientSecret',
      'applicationSecret',
      'tenantSecret',
      'encryptionKey',
      'secret',
      'secretHash',
      '*.accessToken',
      '*.refreshToken',
      '*.access_token',
      '*.refresh_token',
      '*.client_secret',
      '*.secret',
    ],
    censor: '[REDACTED]',
  },
});

export function redactSecrets(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => redactSecrets(entry));
  }
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      const normalized = key.toLowerCase().replace(/[_-]/g, '');
      output[key] = SECRET_KEYS.has(normalized) ? '[REDACTED]' : redactSecrets(child);
    }
    return output;
  }
  if (typeof value === 'string' && looksSensitive(value)) {
    return '[REDACTED]';
  }
  return value;
}

function looksSensitive(value: string): boolean {
  if (value.length < 20) {
    return false;
  }
  return value.startsWith('EAAA') || value.startsWith('sq0csp-') || value.startsWith('eyJ');
}
