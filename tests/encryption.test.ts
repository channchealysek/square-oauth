import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decryptString, encryptString, parseEncryptionKey } from '../src/crypto/encryption.js';
import { redactSecrets } from '../src/logger.js';

describe('encryption', () => {
  const key = crypto.randomBytes(32);

  it('round-trips a token with AES-256-GCM', () => {
    const blob = encryptString('seller-access-token', key, 'max-donuts');
    expect(blob.ciphertext).not.toContain('seller-access-token');
    expect(decryptString(blob, key, 'max-donuts')).toBe('seller-access-token');
  });

  it('rejects a tampered ciphertext, tag, or associated tenant', () => {
    const blob = encryptString('seller-access-token', key, 'max-donuts');
    const tampered = { ...blob, ciphertext: Buffer.from('tampered').toString('base64') };
    expect(() => decryptString(tampered, key, 'max-donuts')).toThrow(/could not be decrypted/);
    const badTag = { ...blob, tag: Buffer.alloc(16, 1).toString('base64') };
    expect(() => decryptString(badTag, key, 'max-donuts')).toThrow(/could not be decrypted/);
    expect(() => decryptString(blob, key, 'other-donuts')).toThrow(/could not be decrypted/);
  });

  it('rejects a different key', () => {
    const blob = encryptString('seller-access-token', key, 'max-donuts');
    expect(() => decryptString(blob, crypto.randomBytes(32), 'max-donuts')).toThrow(/could not be decrypted/);
  });

  it('accepts a 32-byte base64 or hex encryption key and rejects other values', () => {
    const base64 = key.toString('base64');
    const hex = key.toString('hex');
    expect(parseEncryptionKey(base64).equals(key)).toBe(true);
    expect(parseEncryptionKey(hex).equals(key)).toBe(true);
    expect(() => parseEncryptionKey('short')).toThrow(/32 bytes/);
    expect(() => parseEncryptionKey(crypto.randomBytes(16).toString('base64'))).toThrow(/32 bytes/);
  });
});

describe('secret redaction', () => {
  it('redacts token fields and token-shaped values', () => {
    const redacted = redactSecrets({
      accessToken: 'EAAAtestAccesstokenValue123456',
      authorizationStatus: 'connected',
      nested: { refresh_token: 'plain', note: 'sq0csp-super-secret-value' },
    }) as {
      accessToken: string;
      authorizationStatus: string;
      nested: { refresh_token: string; note: string };
    };
    expect(redacted.accessToken).toBe('[REDACTED]');
    expect(redacted.authorizationStatus).toBe('connected');
    expect(redacted.nested.refresh_token).toBe('[REDACTED]');
    expect(redacted.nested.note).toBe('[REDACTED]');
  });
});
