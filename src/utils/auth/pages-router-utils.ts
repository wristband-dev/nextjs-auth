import { NextApiRequest, NextApiResponse } from 'next';

import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../constants';
import { base64ToURLSafe, generateRandomString, sha256Base64 } from '../crypto';
import { LoginState, LoginStateMapConfig } from '../../types';

export function parseTenantSubdomain(request: NextApiRequest, parseTenantFromRootDomain: string): string {
  const { host } = request.headers;

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

export function resolveTenantName(request: NextApiRequest, parseTenantFromRootDomain: string): string {
  if (parseTenantFromRootDomain) {
    return parseTenantSubdomain(request, parseTenantFromRootDomain) || '';
  }

  const { tenant_name: tenantNameParam } = request.query;

  if (!!tenantNameParam && typeof tenantNameParam !== 'string') {
    throw new TypeError('More than one [tenant_name] query parameter was encountered');
  }

  return tenantNameParam || '';
}

export function resolveTenantCustomDomainParam(request: NextApiRequest): string {
  const { tenant_custom_domain: tenantCustomDomainParam } = request.query;

  if (!!tenantCustomDomainParam && typeof tenantCustomDomainParam !== 'string') {
    throw new TypeError('More than one [tenant_custom_domain] query parameter was encountered');
  }

  return tenantCustomDomainParam || '';
}

export function createLoginState(
  request: NextApiRequest,
  redirectUri: string,
  config: LoginStateMapConfig = {}
): LoginState {
  const { return_url: returnUrlParam } = request.query;

  if (!!returnUrlParam && typeof returnUrlParam !== 'string') {
    throw new TypeError('More than one [return_url] query parameter was encountered');
  }

  const returnUrl = config.returnUrl ?? returnUrlParam;

  return {
    state: generateRandomString(32),
    codeVerifier: generateRandomString(32),
    redirectUri,
    ...(!!returnUrl && typeof returnUrl === 'string' ? { returnUrl } : {}),
    ...(!!config.customState && !!Object.keys(config.customState).length ? { customState: config.customState } : {}),
  };
}

export function createLoginStateCookie(
  request: NextApiRequest,
  response: NextApiResponse,
  state: string,
  encryptedLoginState: string,
  dangerouslyDisableSecureCookies: boolean,
  domain?: string
) {
  const { cookies } = request;

  // The max amount of concurrent login state cookies we allow is 3.  If there are already 3 cookies,
  // then we clear the one with the oldest creation timestamp to make room for the new one.
  const responseCookieArray = [];
  const allLoginCookieNames = Object.keys(cookies).filter((cookieName) => {
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
        const staleCookieHeaderValue: string = [
          `${cookieName}=`,
          'Path=/',
          'HttpOnly',
          ...(domain ? [`Domain=${domain}`] : []),
          'SameSite=Lax',
          'Max-Age=0',
          ...(dangerouslyDisableSecureCookies ? [] : ['Secure']),
        ].join('; ');
        responseCookieArray.push(staleCookieHeaderValue);
      }
    });
  }

  // Now add the new login state cookie with a 1-hour expiration time.
  // NOTE: If deploying your own app to production, do not disable secure cookies.
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
  responseCookieArray.push(newCookieHeaderValue);
  response.setHeader('Set-Cookie', responseCookieArray);
}

export async function getAuthorizationUrlParams(
  request: NextApiRequest,
  config: { clientId: string; codeVerifier: string; redirectUri: string; scopes: string[]; state: string }
): Promise<URLSearchParams> {
  const { idp_hint: idpHint, login_hint: loginHint } = request.query;

  if (!!loginHint && typeof loginHint !== 'string') {
    throw new TypeError('More than one [login_hint] query parameter was encountered');
  }

  if (!!idpHint && typeof idpHint !== 'string') {
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
    ...(!!loginHint && typeof loginHint === 'string' ? { login_hint: loginHint } : {}),
    ...(!!idpHint && typeof idpHint === 'string' ? { idp_hint: idpHint } : {}),
  });
}

export function getAndClearLoginStateCookie(
  request: NextApiRequest,
  response: NextApiResponse,
  dangerouslyDisableSecureCookies: boolean,
  domain?: string
): string {
  const { cookies, query } = request;
  const { state } = query;
  const paramState = state ? state.toString() : '';

  // This should always resolve to a single cookie with this prefix, or possibly no cookie at all
  // if it got cleared or expired before the callback was triggered.
  const matchingLoginCookieNames: string[] = Object.keys(cookies).filter((cookieName) => {
    return cookieName.startsWith(`${LOGIN_STATE_COOKIE_PREFIX}${paramState}${LOGIN_STATE_COOKIE_SEPARATOR}`);
  });

  let loginStateCookie: string = '';

  if (matchingLoginCookieNames.length > 0) {
    const cookieName = matchingLoginCookieNames[0];
    loginStateCookie = cookies[cookieName]!;
    // Delete the login state cookie.
    response.setHeader('Set-Cookie', [
      `${cookieName}=; Path=/; HttpOnly${domain ? `; Domain=${domain}` : ''}; SameSite=Lax; Max-Age=0${!dangerouslyDisableSecureCookies ? '; Secure' : ''}`,
    ]);
  }

  return loginStateCookie;
}
