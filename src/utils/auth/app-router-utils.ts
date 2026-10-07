import { NextRequest, NextResponse } from 'next/server';

import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../constants';
import { AppRouterLoginStateCookie, LoginState, LoginStateMapConfig } from '../../types';
import { base64ToURLSafe, generateRandomString, sha256Base64 } from '../crypto';

function parseCookies(cookieHeader: string | null): Record<string, string> {
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split(';').map((cookie) => {
      const [name, ...rest] = cookie.trim().split('=');
      return [name, decodeURIComponent(rest.join('='))];
    })
  );
}

export function parseTenantSubdomain(request: NextRequest, parseTenantFromRootDomain: string): string {
  const host = request.headers.get('host');

  // Should never happen (defensive measure)
  if (!host) {
    return '';
  }

  // Strip off the port if it exists
  const hostname = host.split(':')[0];

  return hostname.substring(hostname.indexOf('.') + 1) === parseTenantFromRootDomain
    ? hostname.substring(0, hostname.indexOf('.'))
    : '';
}

export function resolveTenantName(request: NextRequest, parseTenantFromRootDomain: string): string {
  if (parseTenantFromRootDomain) {
    return parseTenantSubdomain(request, parseTenantFromRootDomain) || '';
  }

  const tenantNameParam = request.nextUrl.searchParams.getAll('tenant_name');

  if (tenantNameParam.length > 1) {
    throw new TypeError('More than one [tenant_name] query parameter was encountered');
  }

  return tenantNameParam[0] || '';
}

export function resolveTenantCustomDomainParam(request: NextRequest): string {
  const tenantCustomDomainParam = request.nextUrl.searchParams.getAll('tenant_custom_domain');

  if (tenantCustomDomainParam.length > 1) {
    throw new TypeError('More than one [tenant_custom_domain] query parameter was encountered');
  }

  return tenantCustomDomainParam[0] || '';
}

export function createLoginState(
  request: NextRequest,
  redirectUri: string,
  config: LoginStateMapConfig = {}
): LoginState {
  const returnUrlParam = request.nextUrl.searchParams.getAll('return_url');

  if (returnUrlParam.length > 1) {
    throw new TypeError('More than one [return_url] query parameter was encountered');
  }

  const resolvedReturnUrlParam = returnUrlParam.length > 0 ? returnUrlParam[0] : '';
  const returnUrl = config.returnUrl ?? resolvedReturnUrlParam;

  return {
    state: generateRandomString(32),
    codeVerifier: generateRandomString(32),
    redirectUri,
    ...(!!returnUrl && typeof returnUrl === 'string' ? { returnUrl } : {}),
    ...(!!config.customState && !!Object.keys(config.customState).length ? { customState: config.customState } : {}),
  };
}

export function createLoginStateCookie(
  request: NextRequest,
  response: NextResponse,
  state: string,
  encryptedLoginState: string,
  dangerouslyDisableSecureCookies: boolean,
  domain?: string
): void {
  // Parse existing cookies from the request
  const cookies = parseCookies(request.headers.get('cookie'));

  // Filter for login state cookies
  const allLoginCookies = Object.entries(cookies)
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
    const staleCookieHeaderValue: string = [
      `${oldestCookie.name}=`,
      'Path=/',
      'HttpOnly',
      ...(domain ? [`Domain=${domain}`] : []),
      'SameSite=Lax',
      'Max-Age=0',
      ...(dangerouslyDisableSecureCookies ? [] : ['Secure']),
    ].join('; ');
    response.headers.append('Set-Cookie', staleCookieHeaderValue);
  }

  // 1 hour expiration for new cookie
  const newCookieName: string = `${LOGIN_STATE_COOKIE_PREFIX}${state}${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now().valueOf()}`;
  const newCookieHeaderValue: string = [
    `${newCookieName}=${encryptedLoginState}`,
    'Path=/',
    'HttpOnly',
    ...(domain ? [`Domain=${domain}`] : []),
    'SameSite=Lax',
    'Max-Age=3600',
    ...(dangerouslyDisableSecureCookies ? [] : ['Secure']),
  ].join('; ');
  response.headers.append('Set-Cookie', newCookieHeaderValue);
}

/**
 * Builds the OAuth2 authorization request params shared by both the app-level and tenant-level
 * Authorize Endpoint URLs. Mirrors pages-router-utils's getAuthorizationUrlParams so that
 * getAppLevelAuthorizationUrl()/getTenantLevelAuthorizationUrl() (common-utils.ts) can be reused
 * identically across both routers.
 */
export async function getAuthorizationUrlParams(
  request: NextRequest,
  config: { clientId: string; codeVerifier: string; redirectUri: string; scopes: string[]; state: string }
): Promise<URLSearchParams> {
  const loginHint = request.nextUrl.searchParams.getAll('login_hint');
  const idpHint = request.nextUrl.searchParams.getAll('idp_hint');

  if (loginHint.length > 1) {
    throw new TypeError('More than one [login_hint] query parameter was encountered');
  }

  if (idpHint.length > 1) {
    throw new TypeError('More than one [idp_hint] query parameter was encountered');
  }

  const digest = await sha256Base64(config.codeVerifier);

  return new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    state: config.state,
    scope: config.scopes.join(' '),
    code_challenge: base64ToURLSafe(digest),
    code_challenge_method: 'S256',
    nonce: generateRandomString(32),
    ...(loginHint.length > 0 ? { login_hint: loginHint[0] } : {}),
    ...(idpHint.length > 0 ? { idp_hint: idpHint[0] } : {}),
  });
}

export function getLoginStateCookie(request: NextRequest): AppRouterLoginStateCookie | null {
  // Parse existing cookies from the request
  const cookies = parseCookies(request.headers.get('cookie'));
  const state = request.nextUrl.searchParams.get('state');
  const paramState = state ? state.toString() : '';

  // This should always resolve to a single cookie with this prefix, or possibly no cookie at all
  // if it got cleared or expired before the callback was triggered.
  const matchingLoginCookieNames: string[] = Object.keys(cookies).filter((cookieName) => {
    return cookieName.startsWith(`${LOGIN_STATE_COOKIE_PREFIX}${paramState}${LOGIN_STATE_COOKIE_SEPARATOR}`);
  });

  if (matchingLoginCookieNames.length > 0) {
    const cookieName = matchingLoginCookieNames[0];
    return { name: cookieName, value: cookies[cookieName] };
  }

  return null;
}

export function clearLoginStateCookie(
  response: NextResponse,
  cookieName: string,
  dangerouslyDisableSecureCookies: boolean,
  domain?: string
): void {
  // NOTE: Due to a bug in iron, we set both maxAge and Expires
  const cookieAttributes: string = [
    `${cookieName}=`,
    'Path=/',
    'HttpOnly',
    ...(domain ? [`Domain=${domain}`] : []),
    'SameSite=Lax',
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    ...(dangerouslyDisableSecureCookies ? [] : ['Secure']),
  ].join('; ');
  response.headers.append('Set-Cookie', cookieAttributes);
}
