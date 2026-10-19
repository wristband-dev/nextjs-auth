import { NextRequest, NextResponse } from 'next/server';

import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../constants';
import { AppRouterLoginStateCookie, LoginConfig } from '../../types';
import { Base64 } from '../base64';
import { generateRandomString } from './common-utils';
import { WristbandError } from '../../error';

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

export function resolveReturnUrl(request: NextRequest, config: LoginConfig = {}): string | undefined {
  // The return URL from the LoginConfig takes priority over the query param.
  if (config.returnUrl) {
    return config.returnUrl;
  }

  const returnUrlParam = request.nextUrl.searchParams.getAll('return_url');

  if (returnUrlParam.length > 1) {
    throw new TypeError('More than one [return_url] query parameter was encountered');
  }

  // If no return URL in either location, return undefined.
  return returnUrlParam[0] || undefined;
}

/**
 * Resolves the protocol the browser used for the incoming request.
 *
 * TLS often terminates at a reverse proxy or hosting platform, so the connection
 * from the proxy to Next.js can be plain HTTP even when the browser used HTTPS.
 * X-Forwarded-Proto carries the original protocol in that case. Only "http" and
 * "https" are accepted; anything else falls back to the protocol of the request URL.
 *
 * This value is used only to validate the post-callback returnUrl, not to make
 * access-control decisions.
 */
function getRequestProtocol(request: NextRequest): string {
  const forwardedProto = request.headers.get('x-forwarded-proto');

  if (forwardedProto) {
    // Proxies may provide a comma-separated list of forwarded protocols.
    const protocol = forwardedProto.split(',')[0].trim().toLowerCase();

    if (protocol === 'http' || protocol === 'https') {
      return protocol;
    }
  }

  // Web requests have no socket to inspect, so fall back to the protocol of the request URL.
  return new URL(request.url).protocol === 'https:' ? 'https' : 'http';
}

/**
 * Validates the returnUrl that the auth callback could potentially redirect the browser
 * to after a successful login, preventing open redirects.
 *
 * An attacker can supply an arbitrary returnUrl through a crafted login link. The
 * returnUrl hostname must match either the hostname that served this request or the
 * configured root domain, so an external host is rejected independently of the
 * protocol check. The protocol check additionally requires the returnUrl to use the
 * same scheme as the incoming request as resolved by getRequestProtocol, which blocks
 * downgrades such as HTTPS to HTTP when that protocol is resolved correctly.
 *
 * This helper does not perform the redirect. The validated URL is returned to the
 * application through the callback result, and the application decides whether and
 * how to use it. Because applications commonly pass it straight to a redirect, this
 * validation is the main safeguard against open redirects, not an optional extra.
 *
 * Returns the validated URL, or undefined if the returnUrl is missing, malformed, or
 * points to a host that isn't allowed.
 */
export function validateReturnUrl(
  request: NextRequest,
  returnUrl: string | undefined,
  tenantName: string,
  applicationAuthorizationRequestsEnabled: boolean,
  parseTenantFromRootDomain?: string
): string | undefined {
  // Safety check: a tenant name is required for validation.
  if (!tenantName) {
    throw new WristbandError('missing_tenant_name', 'Tenant name is required to validate returnUrl');
  }

  // A return URL is optional during login.
  if (!returnUrl) {
    return undefined;
  }

  // Read the Host header rather than request.nextUrl, whose host is the server's own
  // address (e.g. localhost) when running behind a reverse proxy.
  const host = request.headers.get('host');

  // Without a host, the request origin cannot be established safely.
  if (!host) {
    return undefined;
  }

  try {
    // Resolve the incoming request's protocol, accounting for reverse proxies.
    const protocol = getRequestProtocol(request);

    // Parse the request origin using URL rather than splitting the host
    // on colons, which would mishandle IPv6 addresses and ports.
    const requestUrl = new URL(`${protocol}://${host}`);
    const { hostname: requestHostname } = requestUrl;

    // Resolve relative return URLs against the incoming request origin.
    // Absolute URLs ignore the base. URL parsing normalizes URL syntax
    // before the redirect target's protocol and hostname are checked.
    const url = new URL(returnUrl, requestUrl);

    // Only allow redirects to the configured root domain or the exact
    // hostname that served this request, using the same protocol.
    // This rejects external hosts and HTTP/HTTPS protocol downgrades.
    if (
      url.protocol !== `${protocol}:` ||
      (url.hostname !== parseTenantFromRootDomain && url.hostname !== requestHostname)
    ) {
      return undefined;
    }

    // When authorization requests are enabled, rewrite a return URL
    // targeting the root domain to the resolved tenant's subdomain.
    // The URL API preserves the remaining URL components.
    if (
      parseTenantFromRootDomain &&
      applicationAuthorizationRequestsEnabled &&
      url.hostname === parseTenantFromRootDomain
    ) {
      url.hostname = `${tenantName}.${url.hostname}`;
      return url.toString();
    }

    // Preserve the original URL when no tenant rewrite is necessary.
    return returnUrl;
  } catch {
    // Malformed origins or return URLs are treated as unsafe.
    return undefined;
  }
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

  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(config.codeVerifier));

  return new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    state: config.state,
    scope: config.scopes.join(' '),
    code_challenge: Base64.urlEncode(new Uint8Array(digest)),
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
