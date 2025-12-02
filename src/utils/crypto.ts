import { defaults, seal, unseal } from 'iron-webcrypto';
import * as crypto from 'uncrypto';

import { LoginState } from '../types';

export function encodeBase64(input: string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  let binary = '';
  data.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

export function base64ToURLSafe(str: string): string {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function generateRandomString(length: number): string {
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  const base64String = btoa(String.fromCharCode(...randomValues));
  return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export async function sha256Base64(input: string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashString = hashArray
    .map((byte) => {
      return String.fromCharCode(byte);
    })
    .join('');
  return btoa(hashString);
}

export async function encryptLoginState(loginState: LoginState, loginStateSecret: string): Promise<string> {
  const encryptedLoginState: string = await seal(crypto, loginState, loginStateSecret, defaults);

  if (encryptedLoginState.length > 4096) {
    throw new TypeError(
      'Login state cookie exceeds 4kB in size. Ensure your [customState] and [returnUrl] values are a reasonable size.'
    );
  }

  return encryptedLoginState;
}

export async function decryptLoginState(loginStateCookie: string, loginStateSecret: string): Promise<LoginState> {
  const loginState: unknown = await unseal(crypto, loginStateCookie, loginStateSecret, defaults);
  return loginState as LoginState;
}
