import { NextRequest, NextResponse } from 'next/server';

import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../constants';
import { AppRouterLoginStateCookie, LoginState, LoginStateMapConfig } from '../../types';
import { base64ToURLSafe, generateRandomString, sha256Base64 } from './common-utils';

function parseCookies(cookieHeader: string | null): Record<string, string> {
  if (!cookieHeader) return {};
  return Object.fromEntries(
    cookieHeader.split(';').map((cookie) => {
      const [name, ...rest] = cookie.trim().split('=');
      return [name, decodeURIComponent(rest.join('='))];
    })
  );
}

export function parseTenantSubdomain(req: NextRequest, parseTenantFromRootDomain: string): string {
  const host = req.headers.get('host');
  return host!.substring(host!.indexOf('.') + 1) === parseTenantFromRootDomain
    ? host!.substring(0, host!.indexOf('.'))
    : '';
}

export function resolveTenantDomainName(req: NextRequest, parseTenantFromRootDomain: string): string {
  if (parseTenantFromRootDomain) {
    return parseTenantSubdomain(req, parseTenantFromRootDomain) || '';
  }

  const tenantDomainParam = req.nextUrl.searchParams.getAll('tenant_domain');

  if (tenantDomainParam.length > 1) {
    throw new TypeError('More than one [tenant_domain] query parameter was encountered');
  }

  return tenantDomainParam[0] || '';
}

export function resolveTenantCustomDomainParam(req: NextRequest): string {
  const tenantCustomDomainParam = req.nextUrl.searchParams.getAll('tenant_custom_domain');

  if (tenantCustomDomainParam.length > 1) {
    throw new TypeError('More than one [tenant_custom_domain] query parameter was encountered');
  }

  return tenantCustomDomainParam[0] || '';
}

export function createLoginState(req: NextRequest, redirectUri: string, config: LoginStateMapConfig = {}): LoginState {
  const returnUrl = req.nextUrl.searchParams.getAll('return_url');

  if (returnUrl.length > 1) {
    throw new TypeError('More than one [return_url] query parameter was encountered');
  }

  const loginStateData = {
    state: generateRandomString(32),
    codeVerifier: generateRandomString(32),
    redirectUri,
    ...(returnUrl.length > 0 ? { returnUrl: returnUrl[0] } : {}),
    ...(!!config.customState && !!Object.keys(config.customState).length ? { customState: config.customState } : {}),
  };

  return config.customState ? { ...loginStateData, customState: config.customState } : loginStateData;
}

export function createLoginStateCookie(
  req: NextRequest,
  res: NextResponse,
  state: string,
  encryptedLoginState: string,
  dangerouslyDisableSecureCookies: boolean
): void {
  // Parse existing cookies from the request
  const cookies = parseCookies(req.headers.get('cookie'));

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
    defaultTenantCustomDomain?: string;
    defaultTenantDomainName?: string;
    redirectUri: string;
    scopes: string[];
    state: string;
    tenantCustomDomain?: string;
    tenantDomainName?: string;
    isApplicationCustomDomainActive?: boolean;
    wristbandApplicationVanityDomain: string;
  }
): Promise<string> {
  const loginHint = req.nextUrl.searchParams.getAll('login_hint');

  if (loginHint.length > 1) {
    throw new TypeError('More than one [login_hint] query parameter was encountered');
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
    ...(loginHint.length > 0 ? { login_hint: loginHint[0] } : {}),
  });

  const separator = config.isApplicationCustomDomainActive ? '.' : '-';

  // Domain priority order resolution:
  // 1)  tenant_custom_domain query param
  // 2a) tenant subdomain
  // 2b) tenant_domain query param
  // 3)  defaultTenantCustomDomain login config
  // 4)  defaultTenantDomainName login config
  if (config.tenantCustomDomain) {
    return `https://${config.tenantCustomDomain}/api/v1/oauth2/authorize?${queryParams.toString()}`;
  }
  if (config.tenantDomainName) {
    return `https://${config.tenantDomainName}${separator}${config.wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${queryParams.toString()}`;
  }
  if (config.defaultTenantCustomDomain) {
    return `https://${config.defaultTenantCustomDomain}/api/v1/oauth2/authorize?${queryParams.toString()}`;
  }
  return `https://${config.defaultTenantDomainName}${separator}${config.wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?${queryParams.toString()}`;
}

export function getLoginStateCookie(req: NextRequest): AppRouterLoginStateCookie | null {
  // Parse existing cookies from the request
  const cookies = parseCookies(req.headers.get('cookie'));
  const state = req.nextUrl.searchParams.get('state');
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
  res: NextResponse,
  cookieName: string,
  dangerouslyDisableSecureCookies: boolean
): void {
  // NOTE: Due to a bug in iron-session, we set both maxAge and Expires
  const cookieAttributes = [
    `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
    !dangerouslyDisableSecureCookies ? 'Secure' : '',
  ].join('; ');
  res.headers.append('Set-Cookie', cookieAttributes);
}
