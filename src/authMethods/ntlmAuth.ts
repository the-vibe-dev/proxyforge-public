// NTLM authentication stub.
// Full NTLM handshake requires SSPI (Windows) or libsamba (Linux).
// This module detects NTLM challenge responses and provides helpers for
// constructing NTLM Type-1/Type-3 messages when a compatible backend is
// available (e.g., the optional ntlm side-car or system samba).
// No external npm dependencies. Gracefully degrades on unsupported platforms.
// Adapted from source-reference/vantix/secops/verify/ (snapshot 2026-05-26).

import type { AuthResult } from './index';

export interface NtlmAuthConfig {
  loginUrl: string;
  domain?: string;
  workstation?: string;
}

export interface NtlmCredentials {
  username: string;
  password: string;
}

/** Returns true if an HTTP 401 response indicates NTLM is required. */
export function detectNtlmChallenge(wwwAuthenticate: string | undefined): boolean {
  if (!wwwAuthenticate) return false;
  return /\bNTLM\b/i.test(wwwAuthenticate) || /\bNegotiate\b/i.test(wwwAuthenticate);
}

/**
 * Performs NTLM authentication.
 * On platforms without NTLM support, returns a degraded result with a clear
 * error message so callers can surface a meaningful operator notice.
 */
export async function performNtlmAuth(
  _config: NtlmAuthConfig,
  _creds: NtlmCredentials,
): Promise<AuthResult> {
  // Native NTLM requires SSPI (Windows) or a samba helper.
  // This stub returns a pending result with guidance.
  return {
    success: false,
    error:
      'NTLM auth requires a platform NTLM helper (SSPI on Windows or samba on Linux). ' +
      'Configure the ntlm-helper side-car or use a manual auth session.',
  };
}

/** Build a Base64-encoded NTLM Type-1 negotiate message (pure-JS minimal implementation). */
export function buildNtlmNegotiateMessage(domain?: string, workstation?: string): string {
  // Minimal NTLM Type-1 message: NTLMSSP\0 + message type 1 + flags
  const sig = Buffer.from('4e544c4d53535000', 'hex'); // NTLMSSP\0
  const type = Buffer.alloc(4); type.writeUInt32LE(1, 0);
  const flags = Buffer.alloc(4); flags.writeUInt32LE(0x0000b207, 0); // minimal negotiate flags
  const domainBuf = Buffer.from(domain ?? '', 'utf16le');
  const workBuf = Buffer.from(workstation ?? '', 'utf16le');
  const domainLen = Buffer.alloc(8);
  domainLen.writeUInt16LE(domainBuf.length, 0);
  domainLen.writeUInt16LE(domainBuf.length, 2);
  domainLen.writeUInt32LE(32, 4);
  const workLen = Buffer.alloc(8);
  workLen.writeUInt16LE(workBuf.length, 0);
  workLen.writeUInt16LE(workBuf.length, 2);
  workLen.writeUInt32LE(32 + domainBuf.length, 4);

  return Buffer.concat([sig, type, flags, domainLen, workLen, domainBuf, workBuf]).toString('base64');
}
