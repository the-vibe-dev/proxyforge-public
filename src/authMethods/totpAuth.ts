// TOTP companion — RFC 6238 Time-based One-Time Password generator.
// Implements HOTP (RFC 4226) as the underlying primitive.
// No external dependencies — uses Node.js built-in crypto.

import { createHmac } from 'node:crypto';

// ---------------------------------------------------------------------------
// Base32 decoder (RFC 4648, no padding required)
// ---------------------------------------------------------------------------

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input: string): Buffer {
  const cleaned = input.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx < 0) throw new Error(`Invalid base32 character: ${char}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(output);
}

// ---------------------------------------------------------------------------
// HOTP (RFC 4226)
// ---------------------------------------------------------------------------

function hotp(secret: Buffer, counter: number, digits = 6): string {
  // Encode counter as 8-byte big-endian
  const counterBuf = Buffer.alloc(8);
  // JS bitwise ops are 32-bit; handle 64-bit counter as two 32-bit halves
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  counterBuf.writeUInt32BE(high, 0);
  counterBuf.writeUInt32BE(low, 4);

  const hmac = createHmac('sha1', secret).update(counterBuf).digest();

  // Dynamic truncation
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = code % Math.pow(10, digits);
  return String(otp).padStart(digits, '0');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generates a TOTP code per RFC 6238.
 *
 * @param secret  Base32-encoded shared secret (as provided by the authenticator app)
 * @param digits  Number of digits (default 6)
 * @param step    Time step in seconds (default 30)
 * @param now     Override the current time (ms since epoch) — useful for testing
 * @returns       The current TOTP code as a zero-padded string
 */
export function generateTotpCode(
  secret: string,
  digits = 6,
  step = 30,
  now?: number,
): string {
  const time = now !== undefined ? now : Date.now();
  const counter = Math.floor(time / 1000 / step);
  const secretBuf = base32Decode(secret);
  return hotp(secretBuf, counter, digits);
}

/**
 * Validates a TOTP code, checking a window of ±1 step to tolerate clock skew.
 *
 * @param secret  Base32-encoded shared secret
 * @param code    The code to validate
 * @param digits  Number of digits (default 6)
 * @param step    Time step in seconds (default 30)
 * @param now     Override the current time (ms since epoch)
 * @returns       true if valid within the ±1 step window
 */
export function validateTotpCode(
  secret: string,
  code: string,
  digits = 6,
  step = 30,
  now?: number,
): boolean {
  const time = now !== undefined ? now : Date.now();
  const counter = Math.floor(time / 1000 / step);
  const secretBuf = base32Decode(secret);

  for (const delta of [-1, 0, 1]) {
    if (hotp(secretBuf, counter + delta, digits) === code) return true;
  }
  return false;
}
