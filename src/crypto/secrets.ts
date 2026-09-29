import crypto from 'node:crypto';

const SCRYPT_PARAMS = {
  N: 16_384,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024,
} as const;

const KEY_LENGTH = 32;
const HASH_PREFIX = 'v1';

export const TENANT_SECRET_LENGTH = 43;

export function generateTenantSecret(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export async function hashTenantSecret(secret: string): Promise<{ secretSalt: string; secretHash: string }> {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(secret, salt);
  return {
    secretSalt: salt.toString('base64'),
    secretHash: `${HASH_PREFIX}:${hash.toString('base64')}`,
  };
}

export async function verifyTenantSecret(secret: string, secretSalt: string, secretHash: string): Promise<boolean> {
  const parsed = parseStoredHash(secretHash);
  if (!parsed) {
    return false;
  }
  let salt: Buffer;
  try {
    salt = Buffer.from(secretSalt, 'base64');
  } catch {
    return false;
  }
  if (salt.length !== 16) {
    return false;
  }
  const actual = await scrypt(secret, salt);
  if (actual.length !== parsed.length) {
    return false;
  }
  return crypto.timingSafeEqual(actual, parsed);
}

export function isTenantSecretShape(secret: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(secret);
}

export function generateOAuthState(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export function hashOAuthState(state: string): string {
  return crypto.createHash('sha256').update(state, 'utf8').digest('hex');
}

export function isOAuthStateShape(state: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(state);
}

export function fixedEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

const dummySalt = crypto.randomBytes(16);
const dummyHash = crypto.scryptSync('square-oauth-dummy-verifier', dummySalt, KEY_LENGTH, SCRYPT_PARAMS);

export const DUMMY_TENANT_SECRET = {
  secretSalt: dummySalt.toString('base64'),
  secretHash: `${HASH_PREFIX}:${dummyHash.toString('base64')}`,
};

function parseStoredHash(secretHash: string): Buffer | null {
  const [prefix, encoded] = secretHash.split(':');
  if (prefix !== HASH_PREFIX || !encoded) {
    return null;
  }
  const hash = Buffer.from(encoded, 'base64');
  if (hash.length !== KEY_LENGTH) {
    return null;
  }
  return hash;
}

function scrypt(secret: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(secret, salt, KEY_LENGTH, SCRYPT_PARAMS, (error, derived) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(derived);
    });
  });
}
