import crypto from 'node:crypto';

export interface EncryptedBlob {
  ciphertext: string;
  iv: string;
  tag: string;
}

const IV_BYTES = 12;

export function parseEncryptionKey(raw: string): Buffer {
  const trimmed = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'hex');
  }
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed)) {
    throw new Error('ENCRYPTION_KEY must be 32 bytes encoded as base64 or 64 hex characters');
  }
  const normalized = trimmed.replace(/-/g, '+').replace(/_/g, '/');
  const key = Buffer.from(normalized, 'base64');
  if (key.length !== 32) {
    throw new Error('ENCRYPTION_KEY must decode to exactly 32 bytes');
  }
  return key;
}

export function encryptString(plaintext: string, key: Buffer, aad: string): EncryptedBlob {
  assertKey(key);
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
  };
}

export function decryptString(blob: EncryptedBlob, key: Buffer, aad: string): string {
  assertKey(key);
  const iv = Buffer.from(blob.iv, 'base64');
  const tag = Buffer.from(blob.tag, 'base64');
  const ciphertext = Buffer.from(blob.ciphertext, 'base64');
  if (iv.length !== IV_BYTES || tag.length !== 16 || ciphertext.length === 0) {
    throw new Error('Stored credential could not be decrypted');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  try {
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
  } catch {
    throw new Error('Stored credential could not be decrypted');
  }
}

function assertKey(key: Buffer): void {
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes');
  }
}
