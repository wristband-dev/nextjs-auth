import { NextApiRequest, NextApiResponse } from 'next';
import type { TLSSocket } from 'node:tls';

import { LOGIN_STATE_COOKIE_PREFIX, LOGIN_STATE_COOKIE_SEPARATOR } from '../constants';
import { Base64 } from '../base64';
import { LoginConfig } from '../../types';
import { generateRandomString } from './common-utils';
import { WristbandError } from '../../error';

/**
 * Resolves the host the browser used for the incoming request, including any port.
 *
 * By default, only the Host header is used. When trustProxyHeaders is enabled, the first value of the
 * X-Forwarded-Host header is used instead, falling back to the Host header. It should only be enabled
 * when the application runs behind a reverse proxy that sets or overwrites X-Forwarded-Host, since
 * clients can send the header themselves.
 *
 * Returns an empty string if no host can be determined.
 */
function getRequestHost(request: NextApiRequest, trustProxyHeaders: boolean): string {
  if (trustProxyHeaders) {
    const forwardedHostHeader = request.headers['x-forwarded-host'];
    const forwardedHostValue = Array.isArray(forwardedHostHeader) ? forwardedHostHeader[0] : forwardedHostHeader;

    // Proxies may provide a comma-separated list of forwarded hosts.
    const forwardedHost = forwardedHostValue?.split(',')[0].trim();

    if (forwardedHost) {
      return forwardedHost;
    }
  }

  return request.headers.host || '';
}

export function parseTenantSubdomain(
  request: NextApiRequest,
  parseTenantFromRootDomain: string,
  trustProxyHeaders: boolean
): string {
  const host = getRequestHost(request, trustProxyHeaders);

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

export function resolveTenantName(
  request: NextApiRequest,
  parseTenantFromRootDomain: string,
  trustProxyHeaders: boolean
): string {
  if (parseTenantFromRootDomain) {
    return parseTenantSubdomain(request, parseTenantFromRootDomain, trustProxyHeaders) || '';
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

export function resolveReturnUrl(request: NextApiRequest, config: LoginConfig = {}): string | undefined {
  // The return URL from the LoginConfig takes priority over the query param.
  if (config.returnUrl) {
    return config.returnUrl;
  }

  const { return_url: returnUrlParam } = request.query;

  // If no return URL in either location, return undefined.
  if (!returnUrlParam) {
    return undefined;
  }

  if (typeof returnUrlParam !== 'string') {
    throw new TypeError('More than one [return_url] query parameter was encountered');
  }

  return returnUrlParam;
}

/**
 * Resolves the protocol the browser used for the incoming request.
 *
 * TLS often terminates at a reverse proxy or hosting platform, so the connection
 * from the proxy to Next.js can be plain HTTP even when the browser used HTTPS.
 * X-Forwarded-Proto carries the original protocol in that case. Only "http" and
 * "https" are accepted; anything else falls back to whether the direct connection
 * to Node.js is TLS-encrypted.
 *
 * This value is used only to validate the post-callback returnUrl, not to make
 * access-control decisions.
 */
function getRequestProtocol(request: NextApiRequest): string {
  const forwardedProto = request.headers['x-forwarded-proto'];

  if (typeof forwardedProto === 'string') {
    // Proxies may provide a comma-separated list of forwarded protocols.
    const protocol = forwardedProto.split(',')[0].trim().toLowerCase();

    if (protocol === 'http' || protocol === 'https') {
      return protocol;
    }
  }

  // This reflects the connection to Node.js, not necessarily the
  // original client connection when TLS terminates at a reverse proxy.
  // The cast is type-only; plain HTTP sockets leave "encrypted" undefined.
  return (request.socket as TLSSocket).encrypted ? 'https' : 'http';
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
  request: NextApiRequest,
  returnUrl: string | undefined,
  tenantName: string,
  applicationAuthorizationRequestsEnabled: boolean,
  trustProxyHeaders: boolean,
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

  const host = getRequestHost(request, trustProxyHeaders);

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
    ...(!!loginHint && typeof loginHint === 'string' ? { login_hint: loginHint } : {}),
    ...(!!idpHint && typeof idpHint === 'string' ? { idp_hint: idpHint } : {}),
  });
}

export function getLoginStateCookie(request: NextApiRequest): { cookieName: string; loginStateCookie: string } {
  const { cookies, query } = request;
  const { state } = query;
  const paramState = state ? state.toString() : '';

  // This should always resolve to a single cookie with this prefix, or possibly no cookie at all
  // if it got cleared or expired before the callback was triggered.
  const matchingLoginCookieNames: string[] = Object.keys(cookies).filter((cookieName) => {
    return cookieName.startsWith(`${LOGIN_STATE_COOKIE_PREFIX}${paramState}${LOGIN_STATE_COOKIE_SEPARATOR}`);
  });

  if (matchingLoginCookieNames.length > 0) {
    const cookieName = matchingLoginCookieNames[0];
    return { cookieName, loginStateCookie: cookies[cookieName]! };
  }

  return { cookieName: '', loginStateCookie: '' };
}

export function clearLoginStateCookie(
  response: NextApiResponse,
  cookieName: string,
  dangerouslyDisableSecureCookies: boolean,
  domain?: string
): void {
  const cookieAttributes = [
    'HttpOnly',
    ...(domain ? [`Domain=${domain}`] : []),
    'Path=/',
    'Max-Age=0',
    'SameSite=Lax',
    ...(dangerouslyDisableSecureCookies ? [] : ['Secure']),
  ].join('; ');
  response.setHeader('Set-Cookie', [`${cookieName}=; ${cookieAttributes}`]);
}
