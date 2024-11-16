import { cookies } from 'next/headers';
import { NextRequest } from 'next/server';

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

export function createLoginStateCookie(
  state: string,
  encryptedLoginState: string,
  dangerouslyDisableSecureCookies: boolean
) {
  const cookiesList = cookies();
  // The max amount of concurrent login state cookies we allow is 3.  If there are already 3 cookies,
  // then we clear the one with the oldest creation timestamp to make room for the new one.
  const allLoginCookieNames = Object.keys(cookiesList).filter((cookieName) => {
    return cookieName.startsWith(`${LOGIN_STATE_COOKIE_PREFIX}`);
  });

  // Retain only the 2 cookies with the most recent timestamps.
  if (allLoginCookieNames.length >= 3) {
    const mostRecentTimestamps: string[] = allLoginCookieNames
      .map((cookieName: string) => {
        return cookieName.split(LOGIN_STATE_COOKIE_SEPARATOR)[2];
      })
      .sort()
      .reverse()
      .slice(0, 2);

    allLoginCookieNames.forEach((cookieName: string) => {
      const timestamp = cookieName.split(LOGIN_STATE_COOKIE_SEPARATOR)[2];
      // If 3 cookies exist, then we delete the oldest one to make room for the new one.
      if (!mostRecentTimestamps.includes(timestamp)) {
        cookiesList.delete(cookieName);
      }
    });
  }

  // Now add the new login state cookie with a 1-hour expiration time.
  // NOTE: If deploying your own app to production, do not disable secure cookies.
  const newCookieName: string = `${LOGIN_STATE_COOKIE_PREFIX}${state}${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now().valueOf()}`;
  cookiesList.set(newCookieName, encryptedLoginState, {
    httpOnly: true,
    maxAge: 3600,
    path: '/',
    sameSite: 'lax',
    secure: !dangerouslyDisableSecureCookies,
  });
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

export function getAndClearLoginStateCookie(req: NextRequest): string {
  const cookieList = cookies();
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
