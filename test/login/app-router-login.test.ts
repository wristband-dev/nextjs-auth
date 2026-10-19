import { createMocks } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import {
  CLIENT_ID,
  CLIENT_SECRET,
  createMockNextRequest,
  LOGIN_STATE_COOKIE_SECRET,
  parseSetCookies,
} from '../test-utils';
import { LOGIN_STATE_COOKIE_SEPARATOR, STATE_PARAM_MAX_CHAR_LENGTH } from '../../src/utils/constants';
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
        autoConfigureEnabled: false,
      });

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_name=devs4you`,
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
      expect(searchParams.get('idp_hint')).toBeFalsy();

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
      expect(loginStateCookie.domain).toBeUndefined();
      expect(loginStateCookie.path).toBe('/');
      expect(loginStateCookie.samesite).toBe('Lax');
      expect(loginStateCookie.secure).toBe(true);

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState = (await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET)) as LoginState;
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
        autoConfigureEnabled: false,
      });

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_name=devs4you`,
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
      expect(searchParams.get('idp_hint')).toBeFalsy();

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
      expect(loginStateCookie.domain).toBeUndefined();
      expect(loginStateCookie.path).toBe('/');
      expect(loginStateCookie.samesite).toBe('Lax');
      expect(loginStateCookie.secure).toBeUndefined();

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState = (await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET)) as LoginState;
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
      expect(loginState.codeVerifier).toBeTruthy();
      expect(loginState.redirectUri).toBe(redirectUri);
      expect(loginState.customState).toBeUndefined();
      expect(loginState.returnUrl).toBeUndefined();
    });
    test('With login_hint, idp_hint, and return_url query params', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request
      const returnUrl = `https://devs4you.${parseTenantFromRootDomain}/settings`;
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?idp_hint=google&login_hint=${encodeURIComponent('test@wristband.dev')}&return_url=${encodeURIComponent(returnUrl)}`,
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest);

      // Validate Redirect response
      const { headers, status } = response;
      const locationUrl: URL = new URL(headers.get('location')!);
      const { pathname, origin, searchParams } = locationUrl;
      expect(status).toBe(302);
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate query params of Authorize URL
      expect(searchParams.get('login_hint')).toBe('test@wristband.dev');
      expect(searchParams.get('idp_hint')).toBe('google');

      // Validate login state cookie
      const setCookieHeaders = response.headers.getSetCookie();
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

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState = (await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET)) as LoginState;
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.returnUrl).toBe(returnUrl);
    });
  });

  describe('Redirect to Application-level Login/Tenant Discovery', () => {
    test('Unresolved tenant_name and tenant_custom_domain query params', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // tenant_name and tenant_custom_domain query param is missing, which should redirect to app-level login.
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest);
      const location = response.headers.get('location')!;
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('return_url query param is passed as state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const returnUrl = 'https://localhost:6001/settings';
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?return_url=${encodeURIComponent(returnUrl)}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest);
      const location = response.headers.get('location')!;
      expect(location).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}&state=${encodeURIComponent(returnUrl)}`
      );
      expect(response.headers.getSetCookie()).toHaveLength(0);
    });

    test('LoginConfig returnUrl is passed as state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const returnUrl = 'https://localhost:6001/dashboard';
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl });
      const location = response.headers.get('location')!;
      expect(location).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}&state=${encodeURIComponent(returnUrl)}`
      );
    });

    test('LoginConfig returnUrl takes precedence over return_url query param for state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?return_url=${encodeURIComponent('https://localhost:6001/from-query')}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const configReturnUrl = 'https://localhost:6001/from-config';
      const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl: configReturnUrl });
      const location = response.headers.get('location')!;
      expect(location).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}&state=${encodeURIComponent(configReturnUrl)}`
      );
    });

    test('Return URL with its own query string stays encoded inside state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const returnUrl = 'https://localhost:6001/settings?tab=billing&x=1';
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl });
      const location = response.headers.get('location')!;
      const params = new URL(location).searchParams;
      expect(params.get('client_id')).toBe(CLIENT_ID);
      expect(params.get('state')).toBe(returnUrl);
      expect(params.has('tab')).toBe(false);
      expect(params.has('x')).toBe(false);
    });

    test('Return URL at the max state length is passed as state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const prefix = 'https://localhost:6001/';
      const returnUrl = `${prefix}${'a'.repeat(STATE_PARAM_MAX_CHAR_LENGTH - prefix.length)}`;
      expect(returnUrl.length).toBe(STATE_PARAM_MAX_CHAR_LENGTH);

      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl });
      const location = response.headers.get('location')!;
      expect(location).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}&state=${encodeURIComponent(returnUrl)}`
      );
    });

    test('Return URL over the max state length is dropped', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const prefix = 'https://localhost:6001/';
      const returnUrl = `${prefix}${'a'.repeat(STATE_PARAM_MAX_CHAR_LENGTH - prefix.length + 1)}`;
      expect(returnUrl.length).toBe(STATE_PARAM_MAX_CHAR_LENGTH + 1);

      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl });
      const location = response.headers.get('location')!;
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Empty LoginConfig returnUrl and no return_url query param (no state)', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl: '' });
      const location = response.headers.get('location')!;
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest);
      const location = response.headers.get('location')!;
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);

      // App-level authorization requests are not enabled, so the login state cookie is never touched.
      expect(response.headers.getSetCookie()).toHaveLength(0);
    });

    test('Custom application login URL redirect', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://google.com',
        autoConfigureEnabled: false,
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest);
      const location = response.headers.get('location')!;
      // NextResponse.redirect() normalizes a bare origin by adding a trailing slash.
      expect(location).toBe(`https://google.com/?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain with return_url query param passes state', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const returnUrl = `https://${parseTenantFromRootDomain}/settings`;
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?return_url=${encodeURIComponent(returnUrl)}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest);
      const location = response.headers.get('location')!;
      expect(location).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}&state=${encodeURIComponent(returnUrl)}`
      );
      expect(response.headers.getSetCookie()).toHaveLength(0);
    });

    test('Custom application login URL with return URL passes state', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://google.com',
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const returnUrl = `https://${parseTenantFromRootDomain}/settings`;
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.login(mockNextRequest, { returnUrl });
      const location = response.headers.get('location')!;
      // NextResponse.redirect() normalizes a bare origin by adding a trailing slash.
      expect(location).toBe(`https://google.com/?client_id=${CLIENT_ID}&state=${encodeURIComponent(returnUrl)}`);
    });
  });
});
