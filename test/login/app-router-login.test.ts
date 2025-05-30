import { createMocks } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import {
  CLIENT_ID,
  CLIENT_SECRET,
  createMockNextRequest,
  LOGIN_STATE_COOKIE_SECRET,
  parseSetCookies,
} from '../test-utils';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';
import { LoginState } from '../../src/types';
import { decryptLoginState } from '../../src/utils/auth/common-utils';

describe('appRouter.login()', () => {
  let wristbandAuth: WristbandAuth;
  let parseTenantFromRootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    parseTenantFromRootDomain = 'localhost:6001';
    loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
    redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
    wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
  });

  describe('Successful Redirect to Authorize Endpoint', () => {
    test('Default Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
      });

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_domain=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      // Execute the login function using the mock request
      const response = await wristbandAuth.appRouter.login(mockNextRequest);

      // Validate Redirect response
      const { headers, status } = response;
      const locationUrl: URL = new URL(headers.get('location')!);
      const { pathname, origin, searchParams } = locationUrl;

      expect(status).toBe(302);
      expect(origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate no-cache headers
      expect(headers.get('Cache-Control')).toBe('no-store');
      expect(headers.get('Pragma')).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_uri')).toEqual(redirectUri);
      expect(searchParams.get('response_type')).toEqual('code');
      expect(searchParams.get('state')).toBeTruthy();
      expect(searchParams.get('scope')).toEqual('openid offline_access email');
      expect(searchParams.get('code_challenge')).toBeTruthy();
      expect(searchParams.get('code_challenge_method')).toEqual('S256');
      expect(searchParams.get('nonce')).toBeTruthy();
      expect(searchParams.get('login_hint')).toBeFalsy();

      // Validate login state cookie
      const setCookieHeaders = response.headers.getSetCookie();
      expect(setCookieHeaders).toBeTruthy();
      expect(setCookieHeaders).toHaveLength(1);
      const parsedCookies = parseSetCookies(setCookieHeaders);
      const loginStateCookie = parsedCookies[0];
      const cookieKey: string = loginStateCookie.name;
      expect(cookieKey).toBeTruthy();
      const keyParts: string[] = cookieKey.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBeTruthy();
      expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

      expect(loginStateCookie.httponly).toBe(true);
      expect(loginStateCookie['max-age']).toBe('3600');
      expect(loginStateCookie.path).toBe('/');
      expect(loginStateCookie.samesite).toBe('Lax');
      expect(loginStateCookie.secure).toBe(true);

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState: LoginState = await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
      expect(loginState.codeVerifier).toBeTruthy();
      expect(loginState.redirectUri).toBe(redirectUri);
      expect(loginState.customState).toBeUndefined();
      expect(loginState.returnUrl).toBeUndefined();
    });

    test('Dangerously Disable Secure Cookies Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        dangerouslyDisableSecureCookies: true,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
      });

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_domain=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest);

      // Validate Redirect response
      const { headers, status } = response;
      const locationUrl: URL = new URL(headers.get('location')!);
      const { pathname, origin, searchParams } = locationUrl;

      expect(status).toBe(302);
      expect(origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate no-cache headers
      expect(headers.get('Cache-Control')).toBe('no-store');
      expect(headers.get('Pragma')).toBe('no-cache');

      // Validate query params of Authorize URL
      expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
      expect(searchParams.get('redirect_uri')).toEqual(redirectUri);
      expect(searchParams.get('response_type')).toEqual('code');
      expect(searchParams.get('state')).toBeTruthy();
      expect(searchParams.get('scope')).toEqual('openid offline_access email');
      expect(searchParams.get('code_challenge')).toBeTruthy();
      expect(searchParams.get('code_challenge_method')).toEqual('S256');
      expect(searchParams.get('nonce')).toBeTruthy();
      expect(searchParams.get('login_hint')).toBeFalsy();

      // Validate login state cookie
      const setCookieHeaders = response.headers.getSetCookie();
      expect(setCookieHeaders).toBeTruthy();
      expect(setCookieHeaders).toHaveLength(1);
      const parsedCookies = parseSetCookies(setCookieHeaders);
      const loginStateCookie = parsedCookies[0];
      const cookieKey: string = loginStateCookie.name;
      expect(cookieKey).toBeTruthy();
      const keyParts: string[] = cookieKey.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBeTruthy();
      expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

      expect(loginStateCookie.httponly).toBe(true);
      expect(loginStateCookie['max-age']).toBe('3600');
      expect(loginStateCookie.path).toBe('/');
      expect(loginStateCookie.samesite).toBe('Lax');
      expect(loginStateCookie.secure).toBeUndefined();

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState: LoginState = await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
      expect(loginState.codeVerifier).toBeTruthy();
      expect(loginState.redirectUri).toBe(redirectUri);
      expect(loginState.customState).toBeUndefined();
      expect(loginState.returnUrl).toBeUndefined();
    });
  });
});
