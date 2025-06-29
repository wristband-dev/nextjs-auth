import { NextApiRequest, NextApiResponse } from 'next';

import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../constants';
import { LoginState, LoginStateMapConfig } from '../../types';
import { base64ToURLSafe, generateRandomString, sha256Base64 } from './common-utils';

export function parseTenantSubdomain(req: NextApiRequest, parseTenantFromRootDomain: string): string {
  const { host } = req.headers;
  return host!.substring(host!.indexOf('.') + 1) === parseTenantFromRootDomain
    ? host!.substring(0, host!.indexOf('.'))
    : '';
}

export function resolveTenantDomainName(req: NextApiRequest, parseTenantFromRootDomain: string): string {
  if (parseTenantFromRootDomain) {
    return parseTenantSubdomain(req, parseTenantFromRootDomain) || '';
  }

  const { tenant_domain: tenantDomainParam } = req.query;

  if (!!tenantDomainParam && typeof tenantDomainParam !== 'string') {
    throw new TypeError('More than one [tenant_domain] query parameter was encountered');
  }

  return tenantDomainParam || '';
}

export function resolveTenantCustomDomainParam(req: NextApiRequest): string {
  const { tenant_custom_domain: tenantCustomDomainParam } = req.query;

  if (!!tenantCustomDomainParam && typeof tenantCustomDomainParam !== 'string') {
    throw new TypeError('More than one [tenant_custom_domain] query parameter was encountered');
  }

  return tenantCustomDomainParam || '';
}

export function createLoginState(
  req: NextApiRequest,
  redirectUri: string,
  config: LoginStateMapConfig = {}
): LoginState {
  const { return_url: returnUrl } = req.query;

  if (!!returnUrl && typeof returnUrl !== 'string') {
    throw new TypeError('More than one [return_url] query parameter was encountered');
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
  req: NextApiRequest,
  res: NextApiResponse,
  state: string,
  encryptedLoginState: string,
  dangerouslyDisableSecureCookies: boolean
) {
  const { cookies } = req;

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
        const staleCookieHeaderValue = [
          `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${!dangerouslyDisableSecureCookies ? '; Secure' : ''}`,
        ];
        responseCookieArray.push(staleCookieHeaderValue);
      }
    });
  }

  // Now add the new login state cookie with a 1-hour expiration time.
  // NOTE: If deploying your own app to production, do not disable secure cookies.
  const newCookieName: string = `${LOGIN_STATE_COOKIE_PREFIX}${state}${LOGIN_STATE_COOKIE_SEPARATOR}${Date.now().valueOf()}`;
  const newCookieHeaderValue: string = [
    `${newCookieName}=${encryptedLoginState};`,
    'HTTPOnly;',
    'Max-Age=3600;',
    'Path=/;',
    'SameSite=lax',
  ].join(' ');
  const resolvedCookieValue: string = `${newCookieHeaderValue}${dangerouslyDisableSecureCookies ? '' : '; Secure'}`;

  responseCookieArray.push(resolvedCookieValue);
  res.setHeader('Set-Cookie', responseCookieArray);
}

export async function getAuthorizeUrl(
  req: NextApiRequest,
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
  const { login_hint: loginHint } = req.query;

  if (!!loginHint && typeof loginHint !== 'string') {
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
    ...(!!loginHint && typeof loginHint === 'string' ? { login_hint: loginHint } : {}),
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

export function getAndClearLoginStateCookie(
  req: NextApiRequest,
  res: NextApiResponse,
  dangerouslyDisableSecureCookies: boolean
): string {
  const { cookies, query } = req;
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
    res.setHeader('Set-Cookie', [
      `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${!dangerouslyDisableSecureCookies ? '; Secure' : ''}`,
    ]);
  }

  return loginStateCookie;
}
