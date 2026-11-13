'use strict';
import crypto from 'crypto';

/**
 * Time-based one-time passwords (RFC 6238, HMAC-SHA1, 6 digits, 30 s steps),
 * compatible with common authenticator apps. No external dependency.
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOTP_DIGITS = 6;
export const TOTP_PERIOD_SECONDS = 30;

/** RFC 4648 base32 without padding */
export function base32Encode(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function base32Decode(input: string): Buffer {
  const clean = input.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error('invalid base32 character');
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** 160 random bits, the size recommended by RFC 4226 for HMAC-SHA1 */
export function generateTotpSecret(): Buffer {
  return crypto.randomBytes(20);
}

/** HOTP value (RFC 4226) for a counter */
export function hotp(secret: Buffer, counter: number, digits = TOTP_DIGITS): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', secret).update(message).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function totpStep(nowMs: number): number {
  return Math.floor(nowMs / 1000 / TOTP_PERIOD_SECONDS);
}

export function totpCode(secret: Buffer, nowMs: number, digits = TOTP_DIGITS): string {
  return hotp(secret, totpStep(nowMs), digits);
}

/**
 * Checks `code` against the steps around `nowMs` (± `window`). Steps up to
 * `lastUsedStep` are refused, so that a code can't be used twice.
 * @returns the matching step, or `undefined`
 */
export function verifyTotp(
  secret: Buffer,
  code: string,
  nowMs: number,
  window: number,
  lastUsedStep?: number
): number | undefined {
  const normalized = typeof code === 'string' ? code.replace(/\s+/g, '') : '';
  if (!/^\d{6}$/.test(normalized)) {
    return undefined;
  }
  const current = totpStep(nowMs);
  let matched: number | undefined;
  // check every step, without stopping early, to keep the timing constant
  for (let delta = -window; delta <= window; delta++) {
    const step = current + delta;
    const expected = Buffer.from(hotp(secret, step));
    const given = Buffer.from(normalized);
    const equal = crypto.timingSafeEqual(expected, given);
    if (equal && (lastUsedStep === undefined || step > lastUsedStep)) {
      matched = matched ?? step;
    }
  }
  return matched;
}

/** URI for QR codes, see https://github.com/google/google-authenticator/wiki/Key-Uri-Format */
export function otpauthUrl(issuer: string, account: string, secretBase32: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD_SECONDS)
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
