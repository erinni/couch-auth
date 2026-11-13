'use strict';
import crypto from 'crypto';

/**
 * AES-256-GCM encryption for the TOTP secrets stored in the user documents.
 * Format: `v1.<base64url(iv | tag | ciphertext)>`.
 */

const VERSION = 'v1';
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** Decodes `mfa.encryptionKey` (base64, 32 bytes) or throws */
export function parseEncryptionKey(key: string | undefined): Buffer {
  const buffer = Buffer.from(typeof key === 'string' ? key : '', 'base64');
  if (buffer.length !== 32) {
    throw 'mfa.encryptionKey must be 32 bytes encoded as base64 (e.g. `openssl rand -base64 32`).';
  }
  return buffer;
}

export function encryptSecret(plain: Buffer, key: Buffer): string {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${VERSION}.${Buffer.concat([iv, tag, ciphertext]).toString('base64url')}`;
}

export function decryptSecret(boxed: string, key: Buffer): Buffer {
  const [version, payload] = typeof boxed === 'string' ? boxed.split('.') : [];
  if (version !== VERSION || !payload) {
    throw new Error('unsupported secret format');
  }
  const data = Buffer.from(payload, 'base64url');
  const iv = data.subarray(0, IV_BYTES);
  const tag = data.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const ciphertext = data.subarray(IV_BYTES + TAG_BYTES);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
