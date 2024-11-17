import { cookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';

import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../constants';
import { LoginState, LoginStateMapConfig } from '../../types';
import { base64ToURLSafe, generateRandomString, sha256Base64 } from './common-utils';

export function parseTenantSubdomain(req: NextRequest, rootDomain: string): string {
  const host = req.headers.get('host');
  return host!.substring(host!.indexOf('.') + 1) === rootDomain ? host!.substring(0, host!.indexOf('.')) : '';
}

export function resolveTenantDomainName(
  req: NextRequest,
  useTenantSubdomains: boolean,
  rootDomain: string,
  defaultTenantDomainName: string = ''
): string {
  if (useTenantSubdomains) {
    return parseTenantSubdomain(req, rootDomain) || defaultTenantDomainName;
  }

  const tenantDomainParam = req.nextUrl.searchParams.get('tenant_domain');

  if (!!tenantDomainParam && typeof tenantDomainParam !== 'string') {
    throw new TypeError('More than one [tenant_domain] query parameter was passed to the login endpoint');
  }

  return tenantDomainParam || defaultTenantDomainName;
}

export function resolveTenantCustomDomain(req: NextRequest, defaultTenantCustomDomain: string = ''): string {
  const tenantCustomDomainParam = req.nextUrl.searchParams.get('tenant_custom_domain');

  if (!!tenantCustomDomainParam && typeof tenantCustomDomainParam !== 'string') {
    throw new TypeError('More than one [tenant_custom_domain] query parameter was passed to the login endpoint');
  }

  return tenantCustomDomainParam || defaultTenantCustomDomain;
}

export function createLoginState(req: NextRequest, redirectUri: string, config: LoginStateMapConfig = {}): LoginState {
  const returnUrl = req.nextUrl.searchParams.get('return_url');

  if (!!returnUrl && typeof returnUrl !== 'string') {
    throw new TypeError('More than one [return_url] query parameter was passed to the login endpoint');
  }

  const loginStateData = {
    state: generateRandomString(32),
    codeVerifier: generateRandomString(32),
    redirectUri,
    ...(!!returnUrl && typeof returnUrl === 'string' ? { returnUrl } : {}),
    ...(!!config.customState && !!Object.keys(config.customState).length ? { customState: config.customState } : {}),
  };

  return config.customState ? { ...loginStateData, customState: config.customState } : loginStateData;
}

function parseCookies(cookieHeader: string | null): Record<string, string> {
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split(';').map((cookie) => {
      const [name, ...rest] = cookie.trim().split('=');
      return [name, decodeURIComponent(rest.join('='))];
    })
  );
}
export function createLoginStateCookie(
  req: NextRequest,
  res: NextResponse,
  state: string,
  encryptedLoginState: string,
  dangerouslyDisableSecureCookies: boolean
): void {
  // Parse existing cookies from the request
  const existingCookies = parseCookies(req.headers.get('cookie'));

  // Filter for login state cookies
  const allLoginCookies = Object.entries(existingCookies)
    .filter(([name]) => {
      return name.startsWith(LOGIN_STATE_COOKIE_PREFIX);
    })
    .map(([name]) => {
      return { name, timestamp: parseInt(name.split(LOGIN_STATE_COOKIE_SEPARATOR)[2], 10) };
    });

  // The max amount of concurrent login state cookies we allow is 3.  If there are already 3 cookies,
  // then we clear the one with the oldest creation timestamp to make room for the new one.
  if (allLoginCookies.length >= 3) {
    const oldestCookie = allLoginCookies.sort((a, b) => {
      return a.timestamp - b.timestamp;
    })[0];

    // Delete the cookie
    res.headers.append(
      'Set-Cookie',
      `${oldestCookie.name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${!dangerouslyDisableSecureCookies ? '; Secure' : ''}`
    );
  }

  // 1 hour expiration for new cookie
  const newCookieName: string = `${LOGIN_STATE_COOKIE_PREFIX}${state}${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now().valueOf()}`;
  res.headers.append(
    'Set-Cookie',
    `${newCookieName}=${encryptedLoginState}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600${!dangerouslyDisableSecureCookies ? '; Secure' : ''}`
  );
}

export async function getAuthorizeUrl(
  req: NextRequest,
  config: {
    clientId: string;
    codeVerifier: string;
    redirectUri: string;
    scopes: string[];
    state: string;
    tenantCustomDomain?: string;
    tenantDomainName?: string;
    useCustomDomains?: boolean;
    wristbandApplicationDomain: string;
  }
): Promise<string> {
  const loginHint = req.nextUrl.searchParams.get('login_hint');

  if (!!loginHint && typeof loginHint !== 'string') {
    throw new TypeError('More than one [login_hint] query parameter was passed to the login endpoint');
  }

  const digest = await sha256Base64(config.codeVerifier);

  const queryParams = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    state: config.state,
    scope: config.scopes.join(' '),
    code_challenge: base64ToURLSafe(digest),
    code_challenge_method: 'S256',
    nonce: generateRandomString(32),
    ...(!!loginHint && typeof loginHint === 'string' ? { login_hint: loginHint } : {}),
  });

  const separator = config.useCustomDomains ? '.' : '-';
  const tenantDomainToUse =
    config.tenantCustomDomain || `${config.tenantDomainName}${separator}${config.wristbandApplicationDomain}`;
  return `https://${tenantDomainToUse}/api/v1/oauth2/authorize?${queryParams.toString()}`;
}

export async function getAndClearLoginStateCookie(req: NextRequest): Promise<string> {
  const cookieList = await cookies();
  const state = req.nextUrl.searchParams.get('state');
  const paramState = state ? state.toString() : '';

  // This should always resolve to a single cookie with this prefix, or possibly no cookie at all
  // if it got cleared or expired before the callback was triggered.
  const matchingLoginCookieNames: string[] = cookieList
    .getAll()
    .filter((cookie) => {
      return cookie.name.startsWith(`${LOGIN_STATE_COOKIE_PREFIX}${paramState}${LOGIN_STATE_COOKIE_SEPARATOR}`);
    })
    .map((cookie) => {
      return cookie.name;
    });

  let loginStateCookie: string | undefined = '';

  if (matchingLoginCookieNames.length > 0) {
    const cookieName = matchingLoginCookieNames[0];
    loginStateCookie = cookieList.get(cookieName)?.value;
    // Delete the login state cookie.
    cookieList.delete(cookieName);
  }

  return loginStateCookie || '';
}
