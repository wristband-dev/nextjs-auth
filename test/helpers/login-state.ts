/**
 * Test helpers for building and reading login state cookies. Login state encryption now lives in
 * @wristband/typescript-auth, which doesn't export it, so these reimplement the same cookie format
 * (AES-256-GCM, HKDF salt `wristband-login-state-v1`, base64url). Callback tests that use them also
 * confirm the format nextjs-auth relies on hasn't changed.
 */

export const LOGIN_STATE_COOKIE_SEPARATOR = '#';
export const STATE_PARAM_MAX_CHAR_LENGTH = 512;
export const TENANT_NAME_PLACEHOLDER = '{tenant_name}';
export const TENANT_PLACEHOLDER_MSG = '"{tenant_name}" placeholder';

const LOGIN_STATE_MAX_AGE_MS = 3600 * 1000;

export type TestLoginState = {
  codeVerifier: string;
  customState?: Record<string, unknown>;
  redirectUri: string;
  returnUrl?: string;
  state: string;
  tenantCustomDomain?: string;
  tenantName?: string;
};

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

async function deriveKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode('wristband-login-state-v1'),
      info: encoder.encode('aes-gcm-encryption'),
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptLoginState(loginState: TestLoginState, secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    await deriveKey(secret),
    new TextEncoder().encode(JSON.stringify(loginState))
  );
  // [version(1)][timestamp(8)][iv(12)][ciphertext + tag]
  const combined = new Uint8Array(21 + encrypted.byteLength);
  combined[0] = 1;
  new DataView(combined.buffer).setBigUint64(1, BigInt(Date.now()), false);
  combined.set(iv, 9);
  combined.set(new Uint8Array(encrypted), 21);
  return toBase64Url(combined);
}

export async function decryptLoginState(value: string, secret: string): Promise<TestLoginState | null> {
  try {
    const bytes = new Uint8Array(Buffer.from(value, 'base64url'));
    const timestamp = Number(new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(1, false));
    if (bytes[0] !== 1 || Date.now() - timestamp > LOGIN_STATE_MAX_AGE_MS) {
      return null;
    }
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.slice(9, 21), tagLength: 128 },
      await deriveKey(secret),
      bytes.slice(21)
    );
    return JSON.parse(new TextDecoder().decode(decrypted)) as TestLoginState;
  } catch {
    return null;
  }
}
